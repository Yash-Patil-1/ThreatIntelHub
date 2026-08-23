"""Phase 4 tests: report generation lifecycle/artifacts + YARA generation.

SQLite-shimmed per test_api_phase3.py pattern. No network.
"""

import json

import pytest

# ---- sqlite shims (same approach as test_api_phase3.py) --------------------
from sqlalchemy import BigInteger
from sqlalchemy.dialects.postgresql import JSONB, BYTEA, INET, UUID as PGUUID
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _jsonb(type_, compiler, **kw):
    return "JSON"


@compiles(BYTEA, "sqlite")
def _bytea(type_, compiler, **kw):
    return "BLOB"


@compiles(INET, "sqlite")
def _inet(type_, compiler, **kw):
    return "VARCHAR(45)"


@compiles(PGUUID, "sqlite")
def _uuid(type_, compiler, **kw):
    return "CHAR(32)"


@compiles(BigInteger, "sqlite")
def _bigint(type_, compiler, **kw):
    # sqlite only autoincrements INTEGER PRIMARY KEY, not BIGINT
    return "INTEGER"


import app.models  # noqa: E402,F401  (register tables)
from app.models import AuditLog, Ioc, Report  # noqa: E402
from app.reports.generator import complete_report, generate_report  # noqa: E402
from app.yaragen import extract_strings  # noqa: E402

from datetime import datetime, timezone  # noqa: E402


@pytest.fixture()
async def db():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    import uuid as uuid_mod
    for table in app.models.Base.metadata.tables.values():
        for col in table.columns:
            col.server_default = None  # drop now()/gen_random_uuid() DDL defaults
            from sqlalchemy import ColumnDefault, DateTime
            if col.primary_key and isinstance(col.type, PGUUID):
                col.default = ColumnDefault(uuid_mod.uuid4)  # sqlite: no server defaults
            if isinstance(col.type, DateTime) and col.default is None:
                col.default = ColumnDefault(
                    lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    async with engine.begin() as conn:
        await conn.run_sync(app.models.Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def seed_iocs(db, n=3):
    now = datetime.now(timezone.utc)
    for i in range(n):
        db.add(Ioc(type="ip", value_norm=f"10.0.0.{i}", threat_score=90 - i * 10,
                   severity="critical" if i == 0 else "high",
                   first_seen=now, last_seen=now))
    await db.commit()


async def test_report_lifecycle_and_artifacts(db, tmp_path, monkeypatch):
    from app.reports import generator as g

    monkeypatch.setattr(g, "DATA_DIR", tmp_path)
    await seed_iocs(db)
    report = await generate_report(db, kind="daily", limit=50)
    assert report.status == "ready"
    assert report.completed_at is not None

    arts = {a.format: a for a in report.artifacts} if hasattr(report, "artifacts") else None
    # re-query artifacts
    from sqlalchemy import select
    from app.models import ReportArtifact
    rows = (await db.execute(select(ReportArtifact).where(ReportArtifact.report_id == report.id))).scalars().all()
    fmts = {r.format: r.file_path for r in rows}
    assert set(fmts) == {"pdf", "csv", "json", "stix"}

    pdf = open(fmts["pdf"], "rb").read()
    assert pdf[:4] == b"%PDF"
    data = json.loads(open(fmts["json"], "rb").read())
    assert data["kpis"]["total_iocs"] == 3 and len(data["iocs"]) == 3
    stix = json.loads(open(fmts["stix"], "rb").read())
    assert stix["type"] == "bundle" and len(stix["objects"]) == 4  # identity + 3 indicators
    ind = [o for o in stix["objects"] if o.get("type") == "indicator"][0]
    assert ind["pattern"].startswith("[ipv4-addr:value = '10.0.0.")
    csv_text = open(fmts["csv"], "rb").read().decode()
    assert "value_norm" in csv_text.splitlines()[0]


async def test_failed_generation_marks_status(db, tmp_path, monkeypatch):
    from app.reports import generator as g

    monkeypatch.setattr(g, "DATA_DIR", "/proc/definitely-not-writable-xyz")
    await seed_iocs(db)
    report = Report(kind="ondemand", period_start=datetime.now(timezone.utc),
                    period_end=datetime.now(timezone.utc), status="pending")
    db.add(report)
    await db.commit()
    result = await complete_report(db, report)
    assert result.status == "failed"


def test_extract_strings():
    blob = b"AAAAAA this_is_a_long_marker_string\x00short\x00another_unique_marker_here!!"
    strings = extract_strings(blob)
    assert any("this_is_a_long_marker_string" in s for s in strings)
    assert all(len(s) >= 6 for s in strings)


def test_yara_rule_compile_and_match():
    import yara

    class FakeSample:
        sha256 = "ab" * 32
        filename = "evil.exe"
        strings_extracted = ["unique_malware_family_marker_2026", "second_unique_string_xx"]

    rule_text = __import__("app.yaragen", fromlist=["build_rule"]).build_rule(
        FakeSample(), FakeSample.strings_extracted)
    ruleset = yara.compile(source=rule_text)
    buf = ("\n".join(FakeSample.strings_extracted) * 3).encode()
    assert ruleset.match(data=buf), "rule must match synthetic sample buffer"
