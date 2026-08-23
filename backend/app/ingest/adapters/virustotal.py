"""VirusTotal v3 adapter — /api/v3/ip_addresses/{ip}, x-apikey header.

Free tier: 4 req/min, 500 req/day, NON-COMMERCIAL ONLY. Cache TTL 24h.
"""
from app.ingest.adapters.base import BaseAdapter


class VirusTotalAdapter(BaseAdapter):
    source = "virustotal"
    action = "lookup"
    cache_kind = "virustotal"
    cache_ttl_hours = 24
    base_url = "https://www.virustotal.com/api/v3"

    async def enrich_ip(self, ip: str) -> dict | None:
        """Normalized VT reputation for one IP; None if unknown to VT."""
        return await self.cache_before_call(ip, lambda: self._produce_ip(ip))

    async def _produce_ip(self, ip: str) -> dict | None:
        payload = await self._get_json(
            f"{self.base_url}/ip_addresses/{ip}", headers={"x-apikey": self.api_key}
        )
        return normalize_vt_ip(payload)


def normalize_vt_ip(payload: dict | None) -> dict | None:
    """Flatten the JSON:API envelope into {stats, reputation, country, as_owner}."""
    if not payload or "data" not in payload:
        return None
    attrs = payload["data"].get("attributes", {})
    return {
        "id": payload["data"].get("id"),
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "malicious": (attrs.get("last_analysis_stats") or {}).get("malicious", 0),
        "total_engines": sum((attrs.get("last_analysis_stats") or {}).values()),
    }
