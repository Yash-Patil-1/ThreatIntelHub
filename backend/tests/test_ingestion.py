"""Ingestion policy lint + normalize round-trips. No network, no DB."""
import inspect

import pytest

from app.ingest.adapters.abuseipdb import AbuseIPDBAdapter
from app.ingest.adapters.otx import OtxAdapter
from app.ingest.adapters.shodan import InternetDBAdapter, ShodanAdapter
from app.ingest.adapters.virustotal import VirusTotalAdapter
from app.ingest.normalize import normalize

HTTP_MARKERS = ("self._http.", "self._get_json")

ADAPTERS = [OtxAdapter, AbuseIPDBAdapter, ShodanAdapter, InternetDBAdapter, VirusTotalAdapter]


@pytest.mark.parametrize("cls", ADAPTERS, ids=lambda c: c.__name__)
def test_public_methods_guard_before_http(cls):
    """Every public method must check the cache/seen-marker before any HTTP call."""
    for name, method in vars(cls).items():
        if name.startswith("_") or not callable(method):
            continue
        src = inspect.getsource(method)
        http_pos = min((src.find(m) for m in HTTP_MARKERS if src.find(m) != -1), default=-1)
        if http_pos == -1:
            continue  # no HTTP here (delegates via cache_before_call producer)
        cache_before = src.find("cache_before_call") != -1 and src.find("cache_before_call") < http_pos
        # bulk pulls (OTX pages, blacklist) satisfy the policy by seen-marker
        # checks anywhere in the method (per BaseAdapter docstring contract)
        has_marker = ".exists(" in src
        assert cache_before or has_marker, (
            f"{cls.__name__}.{name}: HTTP call without a preceding cache/marker guard"
        )


def test_base_cache_checks_redis_before_producer():
    src = inspect.getsource(ADAPTERS[0].__mro__[1].cache_before_call)
    assert src.find("self._redis.get(") != -1
    assert src.find("self._redis.get(") < src.find("await producer()")


def test_normalize_roundtrips():
    assert normalize("ip", "185.220.101.45") == ("ip", "185.220.101.45")
    assert normalize("ip", " 2001:0DB8::1 ") == ("ip", "2001:db8::1")
    assert normalize("ip", "999.1.1.1") is None
    assert normalize("domain", "EVIL.Example.COM.") == ("domain", "evil.example.com")
    assert normalize("domain", "münchen.de") == ("domain", "xn--mnchen-3ya.de")
    assert normalize("url", "https://Example.com:443/x") == ("url", "https://example.com/x")
    assert normalize("url", "http://user@evil.example.com/a%2Fb?q=1#f") == (
        "url",
        "http://evil.example.com/a/b?q=1",
    )
    assert normalize("sha256", "A" * 64) == ("sha256", "a" * 64)
    assert normalize("sha1", "B" * 41) is None
    assert normalize("md5", "C" * 32) == ("md5", "c" * 32)
