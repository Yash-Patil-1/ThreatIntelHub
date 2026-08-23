"""Shodan adapter — host lookup + zero-key InternetDB enrichment.

Host lookup: GET https://api.shodan.io/shodan/host/{ip}?key=... (~1 req/s free).
NEVER call /shodan/host/search — it burns scan credits (RESEARCH_NOTES.md).
InternetDB (https://internetdb.shodan.io/{ip}) is unauthenticated, courtesy
10/min. Both cached 6h.
"""
from app.ingest.adapters.base import BaseAdapter


class ShodanAdapter(BaseAdapter):
    source = "shodan"
    action = "host"  # sliding ~1/s + count-only daily counter
    cache_kind = "shodan"
    cache_ttl_hours = 6
    base_url = "https://api.shodan.io"

    async def enrich_ip(self, ip: str) -> dict | None:
        return await self.cache_before_call(ip, lambda: self._produce_host(ip))

    async def _produce_host(self, ip: str) -> dict | None:
        payload = await self._get_json(
            f"{self.base_url}/shodan/host/{ip}", params={"key": self.api_key}
        )
        return normalize_host(payload)


class InternetDBAdapter(BaseAdapter):
    """Unauthenticated, no key needed — works even with zero keys configured."""

    source = "internetdb"
    action = "lookup"
    cache_kind = "internetdb"
    cache_ttl_hours = 6
    base_url = "https://internetdb.shodan.io"

    async def lookup_ip(self, ip: str) -> dict | None:
        return await self.cache_before_call(ip, lambda: self._produce_lookup(ip))

    async def _produce_lookup(self, ip: str) -> dict | None:
        return await self._get_json(f"{self.base_url}/{ip}")


def normalize_host(payload: dict | None) -> dict | None:
    if not payload:
        return None
    return {
        "ip": payload.get("ip_str") or payload.get("ip"),
        "ports": sorted(set(payload.get("ports", []))),
        "hostnames": payload.get("hostnames", []),
        "domains": list(dict.fromkeys(payload.get("domains", [])))[:50],
        "org": payload.get("org"),
        "country_code": (payload.get("location") or {}).get("country_code"),
    }
