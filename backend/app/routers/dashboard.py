"""Dashboard summary API (Phase 3.1) — KPIs, 14d trend, geo aggregate.

Backed by Redis key `tih:dash:summary` (BACKEND_SCHEMA.md §Cache keys) with a
60s TTL: the second request within 60s is served from cache without touching
PG. Redis unavailable → fall through to live computation rather than 500ing.
"""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
# Imported into this namespace (resolved at call time) so tests can patch it.
from app.ingest.jobs import get_redis
from app.models import Enrichment, FeedSource, Ioc

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

CACHE_KEY = "tih:dash:summary"
TTL_SECONDS = 60
TREND_DAYS = 14
SEVERITIES = ("critical", "high", "medium", "low", "info")


async def _compute_summary(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)

    total_iocs = (
        await db.execute(select(func.count()).select_from(Ioc))
    ).scalar_one()

    sev_counts = dict.fromkeys(SEVERITIES, 0)
    for sev, n in (
        await db.execute(select(Ioc.severity, func.count()).group_by(Ioc.severity))
    ).all():
        sev_counts[sev] = n

    active_feeds = (
        await db.execute(
            select(func.count()).select_from(FeedSource).where(FeedSource.enabled.is_(True))
        )
    ).scalar_one()

    first_day = (now - timedelta(days=TREND_DAYS - 1)).date()
    per_day = {
        str(d): n
        for d, n in (
            await db.execute(
                select(func.date(Ioc.first_seen), func.count())
                .where(Ioc.first_seen >= datetime.combine(first_day, datetime.min.time()))
                .group_by(func.date(Ioc.first_seen))
            )
        ).all()
    }
    trend = [
        {"date": (first_day + timedelta(days=i)).isoformat(),
         "count": per_day.get((first_day + timedelta(days=i)).isoformat(), 0)}
        for i in range(TREND_DAYS)
    ]

    # Geo aggregate: country codes only exist inside enrichment payloads
    # ('country_code' from AbuseIPDB checks, 'country' from VirusTotal).
    # Honest about availability: empty DB / no enrichments → empty map array.
    # ponytail: python-side scan capped at 5k fresh rows; push into SQL JSON
    # aggregation if the dashboard ever gets slow.
    country_counts: dict[str, int] = {}
    for data in (
        await db.execute(
            select(Enrichment.data).where(Enrichment.expires_at > func.now()).limit(5000)
        )
    ).scalars():
        code = None
        if isinstance(data, dict):
            code = data.get("country_code") or data.get("country")
        if isinstance(code, str) and 2 <= len(code.strip()) <= 3:
            code = code.strip().upper()
            country_counts[code] = country_counts.get(code, 0) + 1
    geo = sorted(
        ({"country_code": k, "count": v} for k, v in country_counts.items()),
        key=lambda r: -r["count"],
    )[:50]

    return {
        "kpis": {
            "total_iocs": total_iocs,
            "by_severity": sev_counts,
            "active_feeds": active_feeds,
        },
        "trend": trend,
        "map": geo,
        "generated_at": now.isoformat(),
    }


@router.get("/summary")
async def dashboard_summary(
    user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    redis = get_redis()
    try:
        cached = await redis.get(CACHE_KEY)
    except Exception:  # noqa: BLE001 — cache outage degrades to live compute
        cached = None
    if cached is not None:
        return json.loads(cached)

    payload = await _compute_summary(db)
    try:
        await redis.set(CACHE_KEY, json.dumps(payload, default=str), ex=TTL_SECONDS)
    except Exception:  # noqa: BLE001 — same degradation on write path
        pass
    return payload
