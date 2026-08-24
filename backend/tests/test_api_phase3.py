"""Phase 3 API tests — dashboard summary, IOC list/detail/lookup/export.

Runs against FastAPI + sqlite+aiosqlite (PG-only column types compiled down via
@compiles overrides; server_defaults stripped so no now()/gen_random_uuid() is
needed at DDL time). Redis replaced by fakeredis. No network, no Docker.
"""
import base64
import math
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from sqlalchemy import BigInteger, select
from sqlalchemy.dialects.postgresql import BYTEA, INET, JSONB, UUID as PGUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool

from app.core.db import get_db
from app.core.security import hash_token, SESSION_COOKIE
from app.main import app
from app.models import ALL_TABLES, AuditLog, Base, Enrichment, FeedSource, Ioc, Sighting, User
from app.models import Session as DbSession
from app.routers import dashboard as dashboard_mod
from app.routers import iocs as iocs_mod

# --- sqlite compatibility shims (test-process only; models untouched) --------


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@compiles(INET, "sqlite")
def _inet_sqlite(type_, compiler, **kw):
    return "VARCHAR"


@compiles(BYTEA, "sqlite")
def _bytea_sqlite(type_, compiler, **kw):
    return "BLOB"


@compiles(PGUUID, "sqlite")
def _uuid_sqlite(type_, compiler, **kw):
    return "CHAR(32)"


@compiles(BigInteger, "sqlite")
def _bigint_sqlite(type_, compiler, **kw):
    # sqlite only autoincrements INTEGER PRIMARY KEY (rowid alias), not BIGINT
    return "INTEGER"


class _NaiveUtcDatetime(datetime):
    """deps.require_admin compares DB expires_at (naive under sqlite) against
    datetime.now(utc) (aware) → TypeError. Auth logic itself is off-limits, so
    tests shim now() to return naive UTC, matching what sqlite hands back."""

    @classmethod
    def now(cls, tz=None):  # noqa: ARG003
        return super().now(timezone.utc).replace(tzinfo=None)


@pytest.fixture()
async def db_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,  # one connection: in-memory db shared across sessions
        connect_args={"check_same_thread": False},
    )
    for table in Base.metadata.tables.values():
        for col in table.columns:
            col.server_default = None  # drop now()/gen_random_uuid() DDL defaults
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def auth_client(db_engine, monkeypatch):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with SessionLocal() as session:
            yield session

    fake_redis = __import__("fakeredis").aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(dashboard_mod, "get_redis", lambda: fake_redis)
    monkeypatch.setattr("app.core.deps.datetime", _NaiveUtcDatetime)

    # Default background-enrichment stub for every test: records ioc_id, no
    # network. Individual tests can re-patch with richer behavior.
    enrich_calls: list[int] = []

    async def stub_enrich(ioc_id):
        enrich_calls.append(ioc_id)

    monkeypatch.setattr(iocs_mod, "run_enrichment", stub_enrich)
    app.dependency_overrides[get_db] = override_get_db

    async with SessionLocal() as s:
        user = User(id=uuid4(), email="admin@example.com", password_hash="x",
                    created_at=datetime.now(timezone.utc))
        s.add(user)
        await s.flush()
        token = secrets.token_urlsafe(32)
        s.add(DbSession(id=uuid4(), user_id=user.id, token_hash=hash_token(token),
                        expires_at=_NaiveUtcDatetime.now() + timedelta(hours=1),
                        created_at=datetime.now(timezone.utc)))
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test",
                           cookies={SESSION_COOKIE: token}) as client:
        client.user_id = user.id
        client.enrich_calls = enrich_calls
        yield client

    app.dependency_overrides.clear()


async def _seed_ioc(session, *, type_="ip", value, severity="info", score=0,
                    last_seen=None, stale=False, tags=None):
    now = last_seen or datetime.now(timezone.utc)
    ioc = Ioc(type=type_, value_norm=value, threat_score=score, severity=severity,
              first_seen=now, last_seen=now, is_stale=stale, tags=tags)
    session.add(ioc)
    await session.flush()
    return ioc


# ------------------------------------------------------------- pure helpers --


def test_cursor_roundtrip():
    ioc = Ioc(id=42, severity="high", threat_score=91,
              first_seen=datetime.now(timezone.utc),
              last_seen=datetime.now(timezone.utc))
    cur = iocs_mod.encode_cursor(ioc)
    rank, ts, ls, cid = iocs_mod.decode_cursor(cur)
    # decode now maps severity -> worst-first rank (critical=0 ... info=4)
    assert (rank, ts, cid) == (iocs_mod.SEVERITIES.index("high"), 91, 42)
    assert ls == ioc.last_seen


def test_decode_rejects_garbage():
    assert iocs_mod.decode_cursor("!!!not-base64!!!") is None
    assert iocs_mod.decode_cursor(base64.urlsafe_b64encode(b"x|y|z").decode()) is None


def _phase3_paths():
    return set(app.openapi()["paths"].keys())


def test_phase3_routes_registered():
    paths = _phase3_paths()
    for p in ("/api/dashboard/summary", "/api/iocs", "/api/iocs/{ioc_id}",
              "/api/iocs/lookup", "/api/iocs/{ioc_id}/enrichment-status",
              "/api/iocs/{ioc_id}/export", "/api/iocs/export"):
        assert p in paths, f"missing route {p}"


# ---------------------------------------------------------------- dashboard --


@pytest.mark.parametrize("path", ["/api/dashboard/summary", "/api/iocs"])
async def test_requires_auth(path):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(path)
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


async def test_dashboard_shape_and_cache(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    async with SessionLocal() as s:
        s.add(FeedSource(slug="otx", display_name="OTX", reliability_weight=0.8))
        s.add(FeedSource(slug="vt", display_name="VT", reliability_weight=1.0, enabled=False))
        await _seed_ioc(s, value="1.1.1.1", severity="critical", score=90,
                        last_seen=now.replace(microsecond=0))
        await _seed_ioc(s, value="evil.example.com", type_="domain")
        await s.commit()

    r1 = await auth_client.get("/api/dashboard/summary")
    assert r1.status_code == 200
    body = r1.json()
    assert body["kpis"]["total_iocs"] == 2
    assert body["kpis"]["by_severity"]["critical"] == 1
    assert body["kpis"]["active_feeds"] == 1  # vt disabled
    assert len(body["trend"]) == 14
    assert sum(d["count"] for d in body["trend"]) >= 1
    assert body["map"] == []  # honest: no enrichments → empty geo array

    # Second request must come from tih:dash:summary cache: mutate DB between
    # calls; if the payload is unchanged the response was served from Redis.
    async with SessionLocal() as s:
        await _seed_ioc(s, value="2.2.2.2")
        await s.commit()
    r2 = await auth_client.get("/api/dashboard/summary")
    assert r2.json()["kpis"]["total_iocs"] == 2  # cached, not recomputed


async def test_dashboard_map_from_enrichments(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    async with SessionLocal() as s:
        fs = FeedSource(slug="abuseipdb", display_name="AIPDB", reliability_weight=0.9)
        s.add(fs)
        await s.flush()
        ioc = await _seed_ioc(s, value="9.9.9.9")
        s.add(Enrichment(ioc_id=ioc.id, feed_source_id=fs.id, data={"country_code": "ru"},
                         fetched_at=now, expires_at=now + timedelta(days=1)))
        s.add(Enrichment(ioc_id=ioc.id, feed_source_id=fs.id + 1000, data={"country_code": "ru"},
                         fetched_at=now, expires_at=now + timedelta(days=1)))
        await s.commit()

    body = (await auth_client.get("/api/dashboard/summary")).json()
    assert {"country_code": "RU", "count": 2} in body["map"]


# -------------------------------------------------------------------- list ---


async def test_list_pagination_keyset(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    async with SessionLocal() as s:
        # severity ASC (alphabetical index order), score DESC within severity
        seeds = [
            ("critical", 90), ("critical", 80), ("critical", 70),
            ("high", 60), ("high", 50), ("info", 10),
        ]
        for i, (sev, sc) in enumerate(seeds):
            await _seed_ioc(s, value=f"10.0.0.{i}", severity=sev, score=sc)
        await s.commit()

    got = []
    cursor = None
    while True:
        params = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        body = (await auth_client.get("/api/iocs", params=params)).json()
        got += [(it["severity"], it["threat_score"]) for it in body["items"]]
        if not body["next_cursor"]:
            break
        cursor = body["next_cursor"]

    assert got == sorted(seeds, key=lambda t: (t[0], -t[1]))
    assert all(len(p) == 2 for p in (got[0:2], got[2:4]))  # limit respected


async def test_list_filters_and_sources(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    async with SessionLocal() as s:
        fs = FeedSource(slug="otx", display_name="OTX", reliability_weight=0.8)
        s.add(fs)
        await s.flush()
        ioc = await _seed_ioc(s, value="185.220.101.45", type_="ip", severity="critical", score=95)
        await _seed_ioc(s, value="benign.example.org", type_="domain", severity="low", score=20)
        s.add(Sighting(ioc_id=ioc.id, feed_source_id=fs.id, external_ref="p1",
                       seen_at=datetime.now(timezone.utc),
                       ingested_at=datetime.now(timezone.utc)))
        await s.commit()

    body = (await auth_client.get("/api/iocs", params={"q": "185."})).json()
    assert len(body["items"]) == 1
    assert body["items"][0]["sources"] == ["otx"]
    assert body["next_cursor"] is None

    body = (await auth_client.get("/api/iocs", params={"severity": "critical"})).json()
    assert len(body["items"]) == 1 and body["items"][0]["type"] == "ip"

    bad = await auth_client.get("/api/iocs", params={"severity": "apocalyptic"})
    assert bad.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    badcur = await auth_client.get("/api/iocs", params={"cursor": "@@@bad@@@"})
    assert badcur.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ------------------------------------------------------------------ detail ---


async def test_detail_breakdown_matches_formula(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    seen_at = datetime.now(timezone.utc) - timedelta(hours=24)
    async with SessionLocal() as s:
        f1 = FeedSource(slug="virustotal", display_name="VT", reliability_weight=1.00)
        f2 = FeedSource(slug="otx", display_name="OTX", reliability_weight=0.60)
        s.add_all([f1, f2])
        await s.flush()
        ioc = await _seed_ioc(s, value="3.3.3.3", tags=["apt"])
        for fs_id, ref in ((f1.id, "v1"), (f2.id, "o1")):
            s.add(Sighting(ioc_id=ioc.id, feed_source_id=fs_id, external_ref=ref,
                           seen_at=seen_at, ingested_at=datetime.now(timezone.utc)))
        await s.commit()

        body = (await auth_client.get(f"/api/iocs/{ioc.id}")).json()

    per = sorted(body["score_breakdown"]["per_source"], key=lambda r: r["source"])
    decay = lambda w: round(w * math.exp(-24 / 720), 4)  # noqa: E731
    assert [(p["source"], p["weight"]) for p in per] == [("otx", 0.6), ("virustotal", 1.0)]
    assert per[0]["decay_contribution"] == decay(0.6)
    assert per[1]["decay_contribution"] == decay(1.0)
    bd = body["score_breakdown"]
    assert bd["cross_source_bonus"] == 15          # 2 distinct sources
    assert bd["sighting_bonus"] == round(math.log2(3) * 5, 4)
    assert body["sightings_count"] == 2
    assert body["tags"] == ["apt"]

    missing = await auth_client.get("/api/iocs/999999")
    assert missing.status_code == status.HTTP_404_NOT_FOUND


# ------------------------------------------------------------------ lookup ---


async def test_lookup_invalid_value_400(auth_client):
    resp = await auth_client.post("/api/iocs/lookup", json={"type": "ip", "value": "999.9.9.9"})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


async def test_lookup_new_ip_202_then_poll(auth_client, monkeypatch):
    called = []

    async def fake_enrich(ioc_id):
        called.append(ioc_id)

    monkeypatch.setattr(iocs_mod, "run_enrichment", fake_enrich)

    resp = await auth_client.post("/api/iocs/lookup", json={"type": "ip", "value": " EVIL.Example.COM ".replace("EVIL.Example.COM", "8.8.8.8")})
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending"
    assert called == [body["ioc_id"]]  # background task ran post-response

    poll = await auth_client.get(f"/api/iocs/{body['ioc_id']}/enrichment-status")
    assert poll.json()["status"] == "pending"  # stub wrote no enrichments

    st = await auth_client.post("/api/iocs/lookup", json={"type": "domain", "value": "plain.example.net"})
    assert st.status_code == 202  # non-ip: created, nothing to enrich, still 202 per contract
    detail = await auth_client.get(f"/api/iocs/{st.json()['ioc_id']}")
    assert detail.json()["value_norm"] == "plain.example.net"


async def test_lookup_fresh_returns_200_detail(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    async with SessionLocal() as s:
        fs = FeedSource(slug="virustotal", display_name="VT", reliability_weight=1.0)
        s.add(fs)
        await s.flush()
        ioc = await _seed_ioc(s, value="5.5.5.5", severity="high", score=66)
        s.add(Enrichment(ioc_id=ioc.id, feed_source_id=fs.id, data={"reputation": 1},
                         fetched_at=now, expires_at=now + timedelta(hours=12)))
        await s.commit()
        ioc_id = ioc.id

    resp = await auth_client.post("/api/iocs/lookup", json={"type": "ip", "value": "5.5.5.5"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cache_hit"] is True
    assert body["ioc"]["id"] == ioc_id
    assert body["ioc"]["severity"] == "high"

    # stale enrichment → back to 202 pending
    async with SessionLocal() as s:
        enr = (await s.execute(select(Enrichment))).scalar_one()
        enr.expires_at = now - timedelta(seconds=1)
        await s.commit()
    resp2 = await auth_client.post("/api/iocs/lookup", json={"type": "ip", "value": "5.5.5.5"})
    assert resp2.status_code == 202


# ------------------------------------------------------------------ export ---


async def test_exports_and_audit_log(auth_client, db_engine):
    SessionLocal = async_sessionmaker(db_engine, expire_on_commit=False)
    async with SessionLocal() as s:
        ioc = await _seed_ioc(s, value="7.7.7.7", severity="medium", score=44)
        await s.commit()
        ioc_id = ioc.id

    csv_resp = await auth_client.get("/api/iocs/export", params={"format": "csv"})
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    lines = csv_resp.text.strip().splitlines()
    assert lines[0].startswith("id,type,value_norm")
    assert any("7.7.7.7" in ln for ln in lines)

    json_resp = await auth_client.get("/api/iocs/export", params={"format": "json"})
    assert json_resp.headers["content-type"].startswith("application/json")
    assert isinstance(json_resp.json(), list) and len(json_resp.json()) == 1

    one = await auth_client.get(f"/api/iocs/{ioc_id}/export", params={"format": "csv"})
    assert one.status_code == 200 and "7.7.7.7" in one.text

    bad = await auth_client.get("/api/iocs/export", params={"format": "pdf"})
    assert bad.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async with SessionLocal() as s:
        rows = (await s.execute(select(AuditLog).where(AuditLog.action == "export"))).scalars().all()
    assert len(rows) == 3  # list csv + list json + single detail export
    assert {r.entity_id for r in rows} == {"list", str(ioc_id)}
