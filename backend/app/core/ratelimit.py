"""Redis-backed fixed/sliding-window rate limiting + daily quota rollups.

Counter keys mirror BACKEND_SCHEMA.md §Redis key schema exactly:
  tih:rl:vt:min / tih:rl:vt:day          — VT 4/min, 500/day
  tih:rl:aipdb:day                       — AbuseIPDB 1000 checks/day
  tih:rl:aipdb:blacklist                 — AbuseIPDB 5 blacklist pulls/day
  tih:rl:shodan:host (sliding ~1/s) + tih:rl:shodan:day (count-only, for rollup)
  tih:rl:internetdb                      — courtesy 10/min on the unauth API
OTX free tier is generous → no rules; we still cache aggressively.
"""
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import FeedSource, QuotaUsage


class QuotaExhaustedError(RuntimeError):
    """Raised when a Redis counter would exceed its configured limit."""

    def __init__(self, key: str, limit: int | None):
        self.key, self.limit = key, limit
        super().__init__(f"quota exhausted: {key} at limit {limit}")


@dataclass(frozen=True)
class Rule:
    key: str
    limit: int | None   # None = count only (never blocks); used for daily rollup totals
    window: float       # seconds; None = resets at next UTC midnight
    sliding: bool = False


DAILY = None  # sentinel window: expiry at next UTC midnight per schema


def _seconds_until_utc_midnight(now: float) -> int:
    dt = datetime.fromtimestamp(now, tz=timezone.utc)
    midnight = dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp() + 86400
    return max(1, int(midnight - now))


RULES: dict[tuple[str, str], tuple[Rule, ...]] = {
    ("virustotal", "lookup"): (
        Rule("tih:rl:vt:min", 4, 60.0),
        Rule("tih:rl:vt:day", 500, DAILY),
    ),
    ("abuseipdb", "check"): (Rule("tih:rl:aipdb:day", 1000, DAILY),),
    ("abuseipdb", "blacklist"): (Rule("tih:rl:aipdb:blacklist", 5, DAILY),),
    ("shodan", "host"): (
        Rule("tih:rl:shodan:host", 1, 1.0, sliding=True),
        Rule("tih:rl:shodan:day", None, DAILY),  # count-only: shodan has no hard daily cap
    ),
    ("internetdb", "lookup"): (Rule("tih:rl:internetdb", 10, 60.0),),
    # ("otx", ...) — generous free tier, uncapped.
}


class RateLimiter:
    def __init__(self, redis, clock=time.time):
        self.redis = redis
        self.clock = clock  # injectable for tests

    async def acquire(self, source: str, action: str) -> None:
        """Check+increment every counter rule for (source, action).

        Raises QuotaExhaustedError on the first exhausted rule; counters already
        incremented by earlier rules in the same call stay incremented — that is
        fine, they only make the quota burn faster and never over-report.
        """
        for rule in RULES.get((source, action), ()):
            if rule.sliding:
                await self._sliding(rule.key, rule.limit, rule.window)
            else:
                await self._fixed(rule)

    async def _fixed(self, rule: Rule) -> None:
        count = await self.redis.incr(rule.key)
        if count == 1:
            ttl = (
                _seconds_until_utc_midnight(self.clock())
                if rule.window is DAILY
                else int(rule.window)
            )
            await self.redis.expire(rule.key, ttl)
        if rule.limit is not None and count > rule.limit:
            raise QuotaExhaustedError(rule.key, rule.limit)

    async def _sliding(self, key: str, limit: int, window: float) -> None:
        now = self.clock()
        member = f"{now:.6f}"
        pipe = self.redis.pipeline(transaction=True)
        pipe.zremrangebyscore(key, "-inf", now - window)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        count = (await pipe.execute())[-1]
        if count > limit:
            await self.redis.zrem(key, member)
            raise QuotaExhaustedError(key, limit)


# --- Daily rollup into Postgres quota_usage -------------------------------

ROLLUP_COUNTER_KEYS: dict[str, list[str]] = {
    "virustotal": ["tih:rl:vt:day"],
    "abuseipdb": ["tih:rl:aipdb:day", "tih:rl:aipdb:blacklist"],
    "shodan": ["tih:rl:shodan:day"],
    "otx": [],
}

# Documented free-tier daily caps (RESEARCH_NOTES.md §API facts).
CALLS_LIMIT: dict[str, int] = {"virustotal": 500, "abuseipdb": 1005, "otx": 0, "shodan": 0}


async def rollup_quota(redis, session: AsyncSession, day: date | None = None) -> None:
    """Persist live Redis counters into quota_usage rows.

    Idempotent upsert keyed UNIQUE(feed_source_id, day): calls_made never goes
    backwards (greatest of existing vs current counter), so re-running a job or
    replaying after a crash can't under-count. quota_violations > 0 means the
    limiter failed to gate something — the dashboard alerts on it.
    """
    today = day or datetime.now(timezone.utc).date()
    slugs = dict((await session.execute(select(FeedSource.slug, FeedSource.id))).all())
    for slug, feed_source_id in slugs.items():
        keys = ROLLUP_COUNTER_KEYS.get(slug, [])
        raw = await redis.mget(keys) if keys else []
        made = sum(int(v) for v in raw if v is not None)
        limit = CALLS_LIMIT.get(slug, 0)
        ins = pg_insert(QuotaUsage).values(
            feed_source_id=feed_source_id,
            day=today,
            calls_made=made,
            calls_limit=limit,
            quota_violations=max(0, made - limit),
        )
        stmt = ins.on_conflict_do_update(
            index_elements=["feed_source_id", "day"],
            set_={
                "calls_made": func.greatest(QuotaUsage.calls_made, ins.excluded.calls_made),
                "calls_limit": ins.excluded.calls_limit,
                "quota_violations": func.greatest(
                    QuotaUsage.quota_violations, ins.excluded.quota_violations
                ),
            },
        )
        await session.execute(stmt)
