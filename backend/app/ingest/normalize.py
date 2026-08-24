"""Value normalization + IOC/sighting persistence pipeline.

Normalization contract (BACKEND_SCHEMA.md iocs.value_norm): lowercased,
URL-decoded, IPs canonicalized, domains punycoded, hashes lowercase.
Upsert is keyed on UNIQUE(type, value_norm); sightings dedupe on
UNIQUE(ioc_id, feed_source_id, external_ref) via ON CONFLICT DO NOTHING —
replaying the same feed payload twice must leave row counts unchanged.

Self-check: `python -m app.ingest.normalize` asserts one example per type.
"""
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit, urlunsplit

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Ioc, Sighting
from app.scoring.engine import recompute_for_ioc

RAW_CAP = 16_384  # sightings.raw capped at 16KB per BACKEND_SCHEMA


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_domain(value: str) -> str | None:
    v = value.strip().lower().rstrip(".")
    if "://" in v:
        v = urlsplit(v).netloc or ""
    v = v.split("/")[0].split(":")[0]  # drop path/port remnants
    if not v or "." not in v and v != "localhost":
        return None
    try:
        return v.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def normalize_url(value: str) -> str | None:
    v = unquote(value.strip())
    parts = urlsplit(v)
    if not parts.scheme or not parts.netloc:
        return None
    host = normalize_domain(parts.hostname or "")
    if host is None:
        return None
    netloc = host
    if parts.port and not ((parts.scheme, parts.port) in (("http", 80), ("https", 443))):
        netloc = f"{host}:{parts.port}"
    # ponytail: only path+query kept (fragment dropped), userinfo stripped —
    # enough for dedupe; add scheme-level canonicalization if feeds disagree.
    return urlunsplit((parts.scheme.lower(), netloc, unquote(parts.path), unquote(parts.query), ""))


_HASH_LEN = {"sha256": 64, "sha1": 40, "md5": 32}


def _normalize_hash(value: str, kind: str) -> str | None:
    v = value.strip().lower()
    return v if len(v) == _HASH_LEN[kind] and all(c in "0123456789abcdef" for c in v) else None


def normalize(kind: str, value: str) -> tuple[str, str] | None:
    """Return (type, value_norm) or None if the value is invalid for the type."""
    match kind:
        case "ip":
            norm = normalize_ip(value)
        case "domain":
            norm = normalize_domain(value)
        case "url":
            norm = normalize_url(value)
        case "sha256" | "sha1" | "md5":
            norm = _normalize_hash(value, kind)
        case _:
            return None
    return (kind, norm) if norm else None


def detect_type(value: str) -> str | None:
    """Best-effort type guess for raw analyst input (⌘K lookup)."""
    for kind in ("ip", "url", "domain", "sha256", "sha1", "md5"):
        if normalize(kind, value):
            # A bare hostname also normalizes as domain; check hash shapes first,
            # then URL (has scheme), then IP, then domain.
            if kind == "domain":
                continue
            return kind
    return "domain" if normalize("domain", value) else None


@dataclass(frozen=True)
class Candidate:
    """One indicator candidate from a feed, pre-normalization."""

    type: str
    value: str
    external_ref: str
    seen_at: datetime | None = None
    tags: list[str] | None = None
    raw: dict | None = None


def cap_raw(raw: dict | None) -> dict | None:
    """Cap the serialized excerpt at RAW_CAP bytes; oversize becomes a truncated string blob."""
    if raw is None:
        return None
    s = json.dumps(raw, default=str)
    if len(s) <= RAW_CAP:
        return raw
    return {"_truncated": s[: RAW_CAP - 32]}  # ponytail: keep head only; full payload lives upstream


async def ingest_candidates(
    session: AsyncSession, feed_source_id: int, candidates: list[Candidate]
) -> dict[str, int]:
    """Upsert IOCs + insert sightings. Returns stats; caller owns commit/rollback."""
    now = datetime.now(timezone.utc)
    stats = {"iocs_touched": 0, "sightings_new": 0}
    touched_ids: set[int] = set()
    for c in candidates:
        norm = normalize(c.type, c.value)
        if norm is None:
            stats["iocs_touched"] += 0
            continue
        itype, ivalue = norm
        seen_at = c.seen_at or now

        ins = pg_insert(Ioc).values(
            type=itype,
            value_norm=ivalue,
            first_seen=seen_at,
            last_seen=seen_at,
            tags=c.tags,
        )
        stmt = (
            ins.on_conflict_do_update(
                index_elements=["type", "value_norm"],
                set_={
                    # never move first_seen backwards; merge tags when present
                    "last_seen": func.greatest(Ioc.last_seen, ins.excluded.last_seen),
                    "tags": func.coalesce(ins.excluded.tags, Ioc.tags),
                },
            )
            .returning(Ioc.id)
        )
        ioc_id = (await session.execute(stmt)).scalar_one()
        stats["iocs_touched"] += 1
        touched_ids.add(ioc_id)

        s_ins = pg_insert(Sighting).values(
            ioc_id=ioc_id,
            feed_source_id=feed_source_id,
            external_ref=c.external_ref,
            seen_at=seen_at,
            raw=cap_raw(c.raw),
        )
        result = await session.execute(
            s_ins.on_conflict_do_nothing(
                index_elements=["ioc_id", "feed_source_id", "external_ref"]
            ).returning(Sighting.id)
        )
        if result.scalar() is not None:
            stats["sightings_new"] += 1

    # Inline recompute: every ingestion caller gets fresh scores automatically.
    # ponytail: one query per touched IOC — fine at feed-run sizes; switch to a
    # single grouped aggregate if blacklist pulls (10K rows) ever get slow.
    for ioc_id in touched_ids:
        await recompute_for_ioc(session, ioc_id)
    return stats


if __name__ == "__main__":
    cases = [
        ("ip", "185.220.101.45", ("ip", "185.220.101.45")),
        ("ip", " 2001:0DB8:0000:0000:0000:0000:0000:0001 ", ("ip", "2001:db8::1")),
        ("ip", "999.1.1.1", None),
        ("domain", "EVIL.Example.COM.", ("domain", "evil.example.com")),
        ("domain", "münchen.de", ("domain", "xn--mnchen-3ya.de")),
        ("domain", "http://bad.host.example/p", ("domain", "bad.host.example")),
        ("url", "http://user@EVIL.Example.com:80/a%2Fb?q=1#frag", ("url", "http://evil.example.com/a/b?q=1")),
        ("url", "https://Example.com:443/x", ("url", "https://example.com/x")),
        ("url", "not a url", None),
        ("sha256", "A" * 64, ("sha256", "a" * 64)),
        ("sha1", "B" * 41, None),
        ("md5", "C" * 32, ("md5", "c" * 32)),
    ]
    for kind, raw, expected in cases:
        got = normalize(kind, raw)
        assert got == expected, f"{kind}({raw!r}): got {got!r}, want {expected!r}"
    assert detect_type("8.8.8.8") == "ip"
    assert detect_type("d" * 64) == "sha256"
    assert detect_type("evil.example.com") == "domain"
    print("normalize self-check: all cases pass")
