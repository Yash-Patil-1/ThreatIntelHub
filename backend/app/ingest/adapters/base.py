"""BaseAdapter — cache-before-call wrapper over every per-target fetch.

Policy (BACKEND_SCHEMA.md §Redis key schema): no adapter spends quota without
checking `tih:ench:{source}:{ioc_hash}` first. On miss, HTTP goes through the
RateLimiter (QuotaExhaustedError propagates); successful payloads are cached
with the per-source TTL.

Bulk/list pulls (OTX pulses, AbuseIPDB blacklist) can't be keyed per-IOC;
instead they MUST check their seen-marker key before doing work:
  - OTX:      tih:otx:pulse:{id}  (30d TTL)
  - blacklist: tih:aipdb:blacklist:{date}
tests/test_ingestion.py::test_policy_no_direct_http enforces both rules.
"""
import hashlib
import json
import logging
from datetime import timedelta

from app.core.ratelimit import QuotaExhaustedError, RateLimiter

log = logging.getLogger(__name__)


def ioc_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


class BaseAdapter:
    source: str = ""            # feed_sources.slug
    action: str = "lookup"      # RateLimiter rule name
    cache_kind: str = ""        # tih:ench:{cache_kind}:{hash} segment
    cache_ttl_hours: int = 12

    def __init__(self, http, redis, limiter: RateLimiter | None = None, api_key: str | None = None):
        # ponytail: http client injected (respx/mockable); never exposed publicly —
        # public methods must route through cache_before_call or marker checks.
        self._http = http
        self._redis = redis
        self.limiter = limiter or RateLimiter(redis)
        self.api_key = api_key

    @property
    def ttl_seconds(self) -> int:
        return int(timedelta(hours=self.cache_ttl_hours).total_seconds())

    async def cache_before_call(self, value: str, producer):
        """Cache-first fetch: tih:ench hit → return; miss → limiter + HTTP + cache store.

        `producer` is a zero-arg coroutine factory performing the actual HTTP call.
        Returns cached-or-fresh payload dict, or None if upstream said not-found.
        """
        key = f"tih:ench:{self.cache_kind}:{ioc_hash(value)}"
        hit = await self._redis.get(key)
        if hit is not None:
            return json.loads(hit)
        try:
            await self.limiter.acquire(self.source, self.action)
        except QuotaExhaustedError:
            log.warning("%s quota exhausted for %s", self.source, value)
            raise
        data = await producer()
        if data is not None:
            await self._redis.set(key, json.dumps(data), ex=self.ttl_seconds)
        return data

    async def _get_json(self, url: str, **kwargs) -> dict | None:
        resp = await self._http.get(url, timeout=30, **kwargs)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
