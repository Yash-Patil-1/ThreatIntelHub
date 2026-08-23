"""Threat scoring engine (Phase 2, BACKEND_SCHEMA.md §scoring).

Pure formula:  Σ(reliability_weight[source] × exp(-hours_ago/720))
             + cross-source bonus (+15 if ≥2 distinct sources, +25 if ≥3)
             + log2(1 + total_sightings) × 5,   capped at 100.

Severity from scripts.seed SEVERITY_THRESHOLDS; below low threshold → 'info'
(iocs.severity CHECK constraint spells it 'info', not 'informational').
"""
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

# scripts/ is a sibling of app/ — make `scripts.seed` importable regardless of cwd.
_BACKEND_ROOT = str(Path(__file__).resolve().parents[2])
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

from scripts.seed import SEVERITY_THRESHOLDS  # noqa: E402

from app.models import FeedSource, Ioc, Sighting  # noqa: E402

RELIABILITY_WEIGHTS: dict[str, float] = {
    "otx": 0.6,
    "abuseipdb": 0.8,
    "virustotal": 0.9,
    "shodan": 0.7,
}
DEFAULT_WEIGHT = 0.5  # unknown feed slug
DECAY_TAU_HOURS = 720.0  # 30-day half-life-ish exponential decay constant


def score_to_severity(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    if score >= SEVERITY_THRESHOLDS["low"]:
        return "low"
    return "info"


def compute_score(sightings) -> tuple[float, str]:
    """Score a list of sightings (dicts or objects with .source/.hours_ago)."""
    weighted = 0.0
    sources: set[str] = set()
    for s in sightings:
        if isinstance(s, dict):
            source, hours = s.get("source"), s.get("hours_ago", 0)
        else:
            source, hours = s.source, s.hours_ago
        weighted += RELIABILITY_WEIGHTS.get(source, DEFAULT_WEIGHT) * math.exp(
            -float(hours) / DECAY_TAU_HOURS
        )
        sources.add(source)
    n = len(sightings)
    bonus = 25 if len(sources) >= 3 else 15 if len(sources) >= 2 else 0
    score = min(weighted + bonus + math.log2(1 + n) * 5, 100.0)
    return score, score_to_severity(score)


async def recompute_for_ioc(session: AsyncSession, ioc_id: int) -> None:
    """Recompute score/severity for one IOC from its sightings; caller commits."""
    now = datetime.now(timezone.utc)
    rows = (
        await session.execute(
            select(FeedSource.slug, Sighting.seen_at)
            .join(FeedSource, FeedSource.id == Sighting.feed_source_id)
            .where(Sighting.ioc_id == ioc_id)
        )
    ).all()
    sightings = [
        {
            "source": slug,
            "hours_ago": max(0.0, (now - seen_at).total_seconds() / 3600),
        }
        for slug, seen_at in rows
    ]
    score, severity = compute_score(sightings)
    await session.execute(
        update(Ioc)
        .where(Ioc.id == ioc_id)
        .values(threat_score=int(round(score)), severity=severity, score_computed_at=now)
    )
