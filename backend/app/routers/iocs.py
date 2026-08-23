"""IOC list/detail/lookup/export API (Phase 3.3–3.6).

Cursor pagination rides the composite index `(severity, threat_score DESC,
last_seen DESC)` — the keyset tuple is base64(severity|threat_score|last_seen
iso|id) with `id` as an ascending tiebreak for stable pages.

Lookup implements BACKEND_SCHEMA §IOCs find-or-enrich: normalize → serve fresh
→ else kick async on-demand enrichment (VT/Shodan/AbuseIPDB adapters; ip-type
only today — those are the only per-target adapters that exist) → 202 pending.
All exports write an audit_log row.
"""
import base64
import csv
import io
import json
import logging
import math
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
from app.core.ratelimit import QuotaExhaustedError, RateLimiter
from app.ingest.adapters.abuseipdb import AbuseIPDBAdapter
from app.ingest.adapters.shodan import ShodanAdapter
from app.ingest.adapters.virustotal import VirusTotalAdapter
from app.ingest.jobs import get_redis, load_api_key
from app.ingest.normalize import detect_type, normalize
from app.models import AuditLog, Enrichment, FeedSource, Ioc, Sighting
from app.scoring.engine import DECAY_TAU_HOURS, recompute_for_ioc

router = APIRouter(prefix="/api/iocs", tags=["iocs"])

log = logging.getLogger(__name__)

TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5")
SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# On-demand enrichment sources: keyed adapters only (InternetDB fallback lives
# in the worker pipeline). ip is the only type these support today.
ON_DEMAND_SOURCES = ("virustotal", "shodan", "abuseipdb")


# ---------------------------------------------------------------- cursors ---

def encode_cursor(row: Ioc) -> str:
    raw = f"{row.severity}|{row.threat_score}|{row.last_seen.isoformat()}|{row.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple | None:
    try:
        sev, score, seen_iso, ioc_id = base64.urlsafe_b64decode(cursor.encode()).decode().split("|")
        return sev, int(score), datetime.fromisoformat(seen_iso), int(ioc_id)
    except Exception:  # noqa: BLE001 — any malformed cursor is just invalid
        return None


def _keyset_after(cur: tuple):
    """WHERE clause selecting rows strictly after the cursor under
    ORDER BY severity ASC, threat_score DESC, last_seen DESC, id ASC."""
    sev, ts, ls, cid = cur
    return or_(
        Ioc.severity > sev,
        (Ioc.severity == sev) & (Ioc.threat_score < ts),
        (Ioc.severity == sev) & (Ioc.threat_score == ts) & (Ioc.last_seen < ls),
        (Ioc.severity == sev) & (Ioc.threat_score == ts) & (Ioc.last_seen == ls) & (Ioc.id > cid),
    )


def _list_filters(type_: str | None, severity: str | None, q: str | None):
    if type_ and type_ not in TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"type must be one of {TYPES}")
    if severity and severity not in SEVERITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"severity must be one of {SEVERITIES}")
    conds = []
    if type_:
        conds.append(Ioc.type == type_)
    if severity:
        conds.append(Ioc.severity == severity)
    if q:
        conds.append(Ioc.value_norm.ilike(f"%{q}%"))
    return conds


def _audit_export(db: AsyncSession, entity_id: str, detail: dict) -> None:
    # `at` set explicitly: server_default covers PG, but be explicit anyway.
    db.add(AuditLog(action="export", entity_type="iocs", entity_id=entity_id,
                    detail=detail, at=datetime.now(timezone.utc)))


# ------------------------------------------------------------------- list ---

async def _page_rows(db: AsyncSession, conds, limit: int):
    stmt = (
        select(Ioc)
        .where(*conds)
        .order_by(Ioc.severity.asc(), Ioc.threat_score.desc(), Ioc.last_seen.desc(), Ioc.id.asc())
        .limit(limit)
    )
    return (await db.execute(stmt)).scalars().all()


async def _sources_for(db: AsyncSession, ids: list[int]) -> dict[int, list[str]]:
    if not ids:
        return {}
    rows = await db.execute(
        select(Sighting.ioc_id, FeedSource.slug)
        .join(FeedSource, FeedSource.id == Sighting.feed_source_id)
        .where(Sighting.ioc_id.in_(ids))
        .distinct()
    )
    out: dict[int, list[str]] = {i: [] for i in ids}
    for ioc_id, slug in rows.all():
        out.setdefault(ioc_id, []).append(slug)
    return out


@router.get("/export")
@router.get("")
async def list_iocs(
    type: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    cursor: str | None = None,
    limit: int = DEFAULT_LIMIT,
    format: str | None = None,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List view (items+next_cursor) or full CSV/JSON export when format= given."""
    conds = _list_filters(type, severity, q)

    if format is not None:
        if format not in ("csv", "json"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "format must be csv|json")
        # ponytail: export streams every matching row unpaginated — add chunked
        # streaming only if a result set ever gets big enough to matter.
        rows = await _page_rows(db, conds, MAX_LIMIT * 10_000)
        _audit_export(db, "list", {"format": format, "count": len(rows)})
        await db.commit()
        return _export_response(rows, format, "iocs")

    cur = decode_cursor(cursor) if cursor else None
    if cursor and cur is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid cursor")
    if cur:
        conds.append(_keyset_after(cur))

    limit = max(1, min(limit, MAX_LIMIT))
    rows = await _page_rows(db, conds, limit + 1)  # fetch one extra for next_cursor
    has_next = len(rows) > limit
    rows = rows[:limit]

    sources = await _sources_for(db, [r.id for r in rows])
    items = [
        {
            "id": r.id, "type": r.type, "value_norm": r.value_norm,
            "threat_score": r.threat_score, "severity": r.severity,
            "sources": sources.get(r.id, []),
            "first_seen": r.first_seen, "last_seen": r.last_seen,
        }
        for r in rows
    ]
    return {"items": items, "next_cursor": encode_cursor(rows[-1]) if has_next and rows else None}


# ----------------------------------------------------------------- detail ---

def _aware(dt: datetime) -> datetime:
    """sqlite returns naive UTC datetimes; asyncpg returns aware. Normalize so
    arithmetic never mixes the two."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


async def _get_ioc_or_404(db: AsyncSession, ioc_id: int) -> Ioc:
    ioc = (await db.execute(select(Ioc).where(Ioc.id == ioc_id))).scalar_one_or_none()
    if ioc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found")
    return ioc


async def _score_breakdown(db: AsyncSession, ioc: Ioc) -> dict:
    """Exact per-source terms behind threat_score so the UI renders DB numbers."""
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(FeedSource.slug, FeedSource.reliability_weight, Sighting.seen_at)
            .join(FeedSource, FeedSource.id == Sighting.feed_source_id)
            .where(Sighting.ioc_id == ioc.id)
        )
    ).all()

    def decay(weight, hours):
        return round(float(weight) * math.exp(-hours / DECAY_TAU_HOURS), 4)

    per_source = []
    sources: set[str] = set()
    for slug, weight, seen_at in rows:
        hours = max(0.0, (now - _aware(seen_at)).total_seconds() / 3600)
        per_source.append({
            "source": slug, "weight": float(weight), "seen_at": seen_at,
            "hours_ago": round(hours, 4), "decay_contribution": decay(weight, hours),
        })
        sources.add(slug)

    n = len(rows)
    cross_bonus = 25 if len(sources) >= 3 else 15 if len(sources) >= 2 else 0
    sighting_bonus = round(math.log2(1 + n) * 5, 4)
    return {
        "per_source": per_source,
        "n_sightings": n,
        "cross_source_bonus": cross_bonus,
        "sighting_bonus": sighting_bonus,
        "formula_version": 1,
    }


@router.get("/{ioc_id}/export")
async def export_ioc(
    ioc_id: int,
    format: str,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if format not in ("csv", "json"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "format must be csv|json")
    ioc = await _get_ioc_or_404(db, ioc_id)
    _audit_export(db, str(ioc.id), {"format": format})
    await db.commit()
    return _export_response([ioc], format, f"ioc_{ioc.id}")


async def _detail_payload(db: AsyncSession, ioc: Ioc) -> dict:
    sightings_count = (
        await db.execute(select(func.count()).select_from(Sighting).where(Sighting.ioc_id == ioc.id))
    ).scalar_one()
    return {
        "id": ioc.id, "type": ioc.type, "value_norm": ioc.value_norm,
        "threat_score": ioc.threat_score, "severity": ioc.severity,
        "tags": ioc.tags, "is_stale": ioc.is_stale,
        "first_seen": ioc.first_seen, "last_seen": ioc.last_seen,
        "sightings_count": sightings_count,
        "score_computed_at": ioc.score_computed_at,
        "score_breakdown": await _score_breakdown(db, ioc),
    }


@router.get("/{ioc_id}")
async def ioc_detail(
    ioc_id: int,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    return await _detail_payload(db, await _get_ioc_or_404(db, ioc_id))


# ------------------------------------------------------------------ export ---

def _jsonable(d: dict) -> dict:
    return {k: v.isoformat() if isinstance(v, datetime) else v for k, v in d.items()}


def _export_response(rows, fmt: str, name: str) -> Response:
    fields = ("id", "type", "value_norm", "threat_score", "severity",
              "first_seen", "last_seen", "is_stale")
    records = [{k: getattr(r, k) for k in fields} for r in rows]
    if fmt == "json":
        content = json.dumps(records, default=str)
        media, ext = "application/json", "json"
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
        content = buf.getvalue()
        media, ext = "text/csv", "csv"
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "format must be csv|json")
    return Response(
        content=content, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}.{ext}"'},
    )


# ------------------------------------------------------------------ lookup ---

class LookupIn(BaseModel):
    # ponytail: type optional — detect_type covers it; explicit type still wins
    type: str | None = None
    value: str


async def run_enrichment(ioc_id: int) -> None:
    """Background task: fetch VT/Shodan/AbuseIPDB data for one ip IOC, upsert
    enrichments, recompute score. Quota exhaustion per source is swallowed
    (BACKEND_SCHEMA contract); other errors logged, never propagated."""
    from app.core.db import SessionLocal

    async with SessionLocal() as session:
        ioc = (await session.execute(select(Ioc).where(Ioc.id == ioc_id))).scalar_one_or_none()
        if ioc is None or ioc.type != "ip":
            return  # no on-demand adapters for non-ip types yet
        feeds = {fs.slug: fs for fs in (await session.execute(select(FeedSource))).scalars()}
        now = datetime.now(timezone.utc)
        async with httpx.AsyncClient(timeout=30) as http:
            for slug in ON_DEMAND_SOURCES:
                feed = feeds.get(slug)
                if feed is None:
                    continue
                api_key = await load_api_key(session, slug)
                limiter = RateLimiter(get_redis())
                match slug:
                    case "virustotal":
                        adapter = VirusTotalAdapter(http, get_redis(), limiter, api_key)
                        call = adapter.enrich_ip(ioc.value_norm)
                    case "shodan":
                        adapter = ShodanAdapter(http, get_redis(), limiter, api_key)
                        call = adapter.enrich_ip(ioc.value_norm)
                    case "abuseipdb":
                        adapter = AbuseIPDBAdapter(http, get_redis(), limiter, api_key)
                        call = adapter.enrich_ip(ioc.value_norm)
                try:
                    data = await call
                except QuotaExhaustedError as exc:
                    log.info("enrichment %s quota exhausted for ioc %s: %s", slug, ioc_id, exc)
                    continue
                except Exception:  # noqa: BLE001 — one bad source never kills the rest
                    log.exception("on-demand enrichment %s failed for ioc %s", slug, ioc_id)
                    continue
                if not isinstance(data, dict) or not data:
                    continue
                enr = (
                    await session.execute(
                        select(Enrichment).where(
                            Enrichment.ioc_id == ioc.id, Enrichment.feed_source_id == feed.id
                        )
                    )
                ).scalar_one_or_none()
                if enr is None:
                    enr = Enrichment(ioc_id=ioc.id, feed_source_id=feed.id)
                    session.add(enr)
                enr.data = data
                enr.fetched_at = now
                enr.expires_at = now + timedelta(seconds=getattr(adapter, "ttl_seconds", 12 * 3600))
        await recompute_for_ioc(session, ioc_id)
        await session.commit()


async def _fresh_enrichments(db: AsyncSession, ioc_id: int) -> int:
    # func.now() keeps the comparison dialect-side (PG timestamptz / sqlite text)
    return (
        await db.execute(
            select(func.count())
            .select_from(Enrichment)
            .where(Enrichment.ioc_id == ioc_id, Enrichment.expires_at > func.now())
        )
    ).scalar_one()


@router.post("/lookup")
async def lookup_ioc(
    body: LookupIn,
    background: BackgroundTasks,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    itype = body.type or detect_type(body.value)
    norm = normalize(itype, body.value)
    if norm is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unrecognized indicator format")
    itype, value_norm = norm

    ioc = (
        await db.execute(select(Ioc).where(Ioc.type == itype, Ioc.value_norm == value_norm))
    ).scalar_one_or_none()
    created = False
    if ioc is None:
        now = datetime.now(timezone.utc)
        # ponytail: select-then-insert instead of PG ON CONFLICT — sqlite-testable;
        # UNIQUE(type,value_norm) still guards races, IntegrityError → refetch later.
        ioc = Ioc(type=itype, value_norm=value_norm, first_seen=now, last_seen=now)
        db.add(ioc)
        await db.flush()
        created = True

    fresh = await _fresh_enrichments(db, ioc.id)
    if not created and fresh > 0:
        # Fresh: serve full detail straight from DB.
        detail = dict(await _detail_payload(db, ioc))
        detail.pop("score_breakdown", None)  # keep lookup payload lean
        await db.commit()
        return JSONResponse(status_code=200, content={"ioc": _jsonable(detail), "cache_hit": True})

    background.add_task(run_enrichment, ioc.id)
    await db.commit()
    return JSONResponse(status_code=202, content={"ioc_id": ioc.id, "status": "pending"})


@router.get("/{ioc_id}/enrichment-status")
async def enrichment_status(
    ioc_id: int,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    ioc = await _get_ioc_or_404(db, ioc_id)
    fresh = await _fresh_enrichments(db, ioc.id)
    return {
        "ioc_id": ioc.id,
        "status": "done" if fresh > 0 or ioc.type != "ip" else "pending",
        "fresh_sources": fresh,
    }
