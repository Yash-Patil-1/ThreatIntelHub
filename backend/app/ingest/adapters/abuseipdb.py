"""AbuseIPDB v2 adapter — daily blacklist download + single-IP check.

Free tier: 1000 checks/day, 5 blacklist pulls/day (10K rows). Header `Key:`.
Blacklist is a bulk pull → date-marker dedupe, not per-IOC cache. Cache TTL 12h.
"""
from datetime import datetime, timezone

from app.ingest.adapters.base import BaseAdapter
from app.ingest.normalize import Candidate

BLACKLIST_MARKER = "tih:aipdb:blacklist:{day}"


class AbuseIPDBAdapter(BaseAdapter):
    source = "abuseipdb"
    action = "check"
    cache_kind = "abuseipdb"
    cache_ttl_hours = 12
    base_url = "https://api.abuseipdb.com/api/v2"

    async def enrich_ip(self, ip: str) -> dict | None:
        """Single-IP abuse-confidence check (spends the 1000/day budget)."""
        return await self.cache_before_call(ip, lambda: self._produce_check(ip))

    async def _produce_check(self, ip: str) -> dict | None:
        payload = await self._get_json(
            f"{self.base_url}/check",
            params={"ipAddress": ip, "maxAgeInDays": 30},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        return normalize_check(payload)

    async def download_blacklist(self, *, confidence_minimum: int = 90) -> list[Candidate]:
        """Daily blacklist pull. Marker key makes repeat same-day runs free."""
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        marker = BLACKLIST_MARKER.format(day=day)
        if await self._redis.exists(marker):
            return []
        await self.limiter.acquire("abuseipdb", "blacklist")
        payload = await self._get_json(
            f"{self.base_url}/blacklist",
            params={"confidenceMinimum": confidence_minimum},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        await self._redis.set(marker, 1, ex=86400)
        return parse_blacklist(payload)


def normalize_check(payload: dict | None) -> dict | None:
    if not payload or "data" not in payload:
        return None
    d = payload["data"]
    return {
        "ip": d.get("ipAddress"),
        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "is_tor": bool(d.get("isTor")),
        "country_code": d.get("countryCode"),
    }


def parse_blacklist(payload: dict | None) -> list[Candidate]:
    if not payload:
        return []
    day = datetime.now(timezone.utc).date().isoformat()
    out = []
    for row in payload.get("data", []):
        out.append(
            Candidate(
                type="ip",
                value=row["ipAddress"],
                external_ref=f"blacklist:{day}:{row['ipAddress']}",
                seen_at=_parse_ts(row.get("lastSeenAt")),
                tags=["abuseipdb-blacklist"],
                raw=row,
            )
        )
    return out


def _parse_ts(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
