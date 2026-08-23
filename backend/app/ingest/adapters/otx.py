"""AlienVault OTX adapter — hourly subscribed-pulse pull, X-OTX-API-KEY header.

Bulk stream pull: dedupe is via seen-markers `tih:otx:pulse:{id}` (30d TTL),
NOT per-IOC cache — the /pulses/subscribed endpoint is one call regardless of
how many pulses are new. OTX free tier is generous; no limiter rules.
"""
import logging

from app.ingest.adapters.base import BaseAdapter
from app.ingest.normalize import Candidate

log = logging.getLogger(__name__)

PULSE_MARKER = "tih:otx:pulse:{id}"
PULSE_MARKER_TTL = 30 * 86400

# OTX indicator type → our iocs.type. Unmappable types (CIDR, email, mutex,
# FilePath, FileHash-PEHASH…) are skipped — iocs.type has a CHECK constraint.
TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
}


class OtxAdapter(BaseAdapter):
    source = "otx"
    cache_kind = "otx"
    cache_ttl_hours = 12  # used only if we later add per-indicator enrichment calls
    base_url = "https://otx.alienvault.com/api/v1"

    @property
    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key}

    async def pull_pulses(self, *, max_pages: int = 25, page_size: int = 20) -> list[Candidate]:
        """Page through subscribed pulses; skip already-seen pulse IDs.

        Stops at a page with no unseen pulses or after max_pages — keeps an
        hourly run bounded even when the subscription grows.
        """
        candidates: list[Candidate] = []
        offset = 0
        for _ in range(max_pages):
            payload = await self._get_json(
                f"{self.base_url}/pulses/subscribed",
                params={"limit": page_size, "offset": offset},
                headers=self._headers,
            )
            results = (payload or {}).get("results", [])
            if not results:
                break
            new_here = 0
            for pulse in results:
                pid = str(pulse.get("id"))
                marker = PULSE_MARKER.format(id=pid)
                if await self._redis.exists(marker):
                    continue
                new_here += 1
                candidates.extend(parse_pulse(pulse))
                await self._redis.set(marker, 1, ex=PULSE_MARKER_TTL)
            if new_here == 0:
                break
            offset += len(results)
        return candidates


def parse_pulse(pulse: dict) -> list[Candidate]:
    """Extract IOC candidates from one pulse payload."""
    tags = [t for t in (pulse.get("tags") or [])][:20]
    out = []
    for ind in pulse.get("indicators", []):
        itype = TYPE_MAP.get(ind.get("type"))
        value = (ind.get("indicator") or "").strip()
        if itype is None or not value:
            continue
        ref = f"{pulse.get('id')}:{ind.get('id')}"
        out.append(
            Candidate(
                type=itype,
                value=value,
                external_ref=f"pulse:{ref}",
                seen_at=_parse_ts(ind.get("created")),
                tags=tags or None,
                raw={"pulse_id": pulse.get("id"), "indicator_id": ind.get("id")},
            )
        )
    return out


def _parse_ts(value: str | None):
    if not value:
        return None
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=None)
    except ValueError:
        return None
