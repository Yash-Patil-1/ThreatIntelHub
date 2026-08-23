"""Ingestion job orchestration: key loading (Fernet), health bookkeeping,
feed runs, and end-of-job quota rollup. Called by workers/worker.py APScheduler
jobs and reusable from tests/on-demand endpoints.
"""
import logging
import time

import httpx
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.core.ratelimit import QuotaExhaustedError, RateLimiter, rollup_quota
from app.core.security import decrypt_key, get_fernet
from app.ingest.adapters.abuseipdb import AbuseIPDBAdapter
from app.ingest.adapters.otx import OtxAdapter
from app.ingest.normalize import ingest_candidates
from app.models import ApiKey, FeedHealth, FeedSource

log = logging.getLogger(__name__)

# Reliability weights from BACKEND_SCHEMA.md scoring formula; display names for seeding.
FEED_DEFAULTS = {
    "otx": ("AlienVault OTX", 0.80),
    "virustotal": ("VirusTotal", 1.00),
    "abuseipdb": ("AbuseIPDB", 0.90),
    "shodan": ("Shodan", 0.60),
}

_redis_client = None


def get_redis():
    """Lazy shared Redis client (decode_responses so counters come back as str)."""
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as aioredis

        from app.core.config import settings

        _redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def get_or_create_feed(session: AsyncSession, slug: str) -> FeedSource:
    feed = (
        await session.execute(select(FeedSource).where(FeedSource.slug == slug))
    ).scalar_one_or_none()
    if feed is None:
        name, weight = FEED_DEFAULTS[slug]
        feed = FeedSource(slug=slug, display_name=name, reliability_weight=weight)
        session.add(feed)
        await session.flush()
    return feed


async def load_api_key(session: AsyncSession, slug: str) -> str | None:
    """Fernet-decrypt the provider key from api_keys; None when not configured."""
    row = (
        await session.execute(
            select(ApiKey).join(FeedSource, FeedSource.id == ApiKey.feed_source_id).where(
                FeedSource.slug == slug, ApiKey.is_configured.is_(True)
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    try:
        return decrypt_key(get_fernet(), bytes(row.encrypted_key))
    except Exception:  # noqa: BLE001 — bad master key must never crash the worker loop
        log.exception("failed to decrypt api key for %s", slug)
        return None


async def record_health(
    session: AsyncSession,
    feed_source_id: int,
    *,
    status: str,
    error: str | None = None,
    items: int = 0,
    duration_ms: float | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    row = (
        await session.execute(select(FeedHealth).where(FeedHealth.feed_source_id == feed_source_id))
    ).scalar_one_or_none()
    if row is None:
        row = FeedHealth(feed_source_id=feed_source_id)
        session.add(row)
    row.last_attempt_at = now
    row.last_status = status
    row.last_error = error[:500] if error else None  # schema: truncated to 500 chars
    row.items_last_run = items
    if duration_ms is not None:
        row.duration_ms_last_run = round(duration_ms)
    if status == "ok":
        row.last_success_at = now
        row.consecutive_failures = 0
    elif status != "disabled":
        row.consecutive_failures += 1
    row.updated_at = now


# ponytail: per-slug closures instead of an adapter registry/factory class —
# two scheduled feeds today; a third means adding one line to this dict.
async def _ingest_otx(session: AsyncSession, feed: FeedSource, api_key: str) -> int:
    async with httpx.AsyncClient(timeout=30) as http:
        adapter = OtxAdapter(http, get_redis(), RateLimiter(get_redis()), api_key)
        candidates = await adapter.pull_pulses()
    stats = await ingest_candidates(session, feed.id, candidates)
    return stats["sightings_new"]


async def _ingest_abuseipdb(session: AsyncSession, feed: FeedSource, api_key: str) -> int:
    async with httpx.AsyncClient(timeout=30) as http:
        adapter = AbuseIPDBAdapter(http, get_redis(), RateLimiter(get_redis()), api_key)
        candidates = await adapter.download_blacklist()
    stats = await ingest_candidates(session, feed.id, candidates)
    return stats["sightings_new"]


INGESTORS = {"otx": _ingest_otx, "abuseipdb": _ingest_abuseipdb}


async def run_ingest_job(slug: str, *, session_factory=SessionLocal) -> str:
    """Run one feed ingestion end-to-end.

    Returns final health status: ok | disabled | quota_exhausted | error.
    Missing key → health=disabled, zero errors raised (graceful degradation).
    Always writes the quota_usage daily rollup at the end.
    """
    async with session_factory() as session:
        feed = await get_or_create_feed(session, slug)
        api_key = await load_api_key(session, slug)
        if api_key is None:
            log.info("feed %s has no API key configured — marking disabled", slug)
            await record_health(session, feed.id, status="disabled")
            await session.commit()
            return "disabled"

        t0 = time.perf_counter()
        status, error, items = "ok", None, 0
        try:
            items = await INGESTORS[slug](session, feed, api_key)
        except QuotaExhaustedError as exc:
            await session.rollback()
            status, error = "quota_exhausted", str(exc)
        except Exception as exc:  # noqa: BLE001 — one bad feed must not kill the worker
            await session.rollback()
            status, error = "error", f"{type(exc).__name__}: {exc}"
            log.exception("ingest job %s failed", slug)

        duration_ms = (time.perf_counter() - t0) * 1000
        await record_health(session, feed.id, status=status, error=error, items=items,
                            duration_ms=None if status != "ok" else duration_ms)
        try:
            await rollup_quota(get_redis(), session)
        except Exception:  # noqa: BLE001 — rollup failure shouldn't mask run status
            log.exception("quota rollup failed for %s", slug)
        await session.commit()
        log.info("feed %s ingest finished: status=%s items=%d", slug, status, items)
        return status
