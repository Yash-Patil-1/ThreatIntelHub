"""Scoring engine tests — pure functions, golden vector + decay + boundaries."""
import math

import pytest

from app.scoring.engine import compute_score, score_to_severity


def test_golden_vector_three_sources():
    # Hand-computed: (0.9+0.8+0.7)*exp(0) + 25 (3 distinct sources) + log2(4)*5
    #             = 2.4 + 25 + 10 = 37.4 → low (< 40)
    score, severity = compute_score(
        [
            {"source": "virustotal", "hours_ago": 0},
            {"source": "abuseipdb", "hours_ago": 0},
            {"source": "shodan", "hours_ago": 0},
        ]
    )
    assert score == pytest.approx(37.4)
    assert severity == "low"


def test_decay_single_old_sighting():
    # otx sighting exactly one tau old: 0.6*e^-1 + log2(2)*5 = 5.2207… → info
    score, severity = compute_score([{"source": "otx", "hours_ago": 720}])
    assert score == pytest.approx(0.6 * math.exp(-1) + 5)
    assert severity == "info"


def test_unknown_source_default_weight():
    # unknown slug → weight 0.5: 0.5*exp(0) + 0 + log2(2)*5 = 5.5 → info
    score, _ = compute_score([{"source": "mysteryfeed", "hours_ago": 0}])
    assert score == pytest.approx(5.5)


def test_object_sightings_supported():
    class S:
        source = "abuseipdb"
        hours_ago = 0

    score, severity = compute_score([S()])
    assert score == pytest.approx(0.8 + math.log2(2) * 5)
    assert severity == "info"


def test_score_capped_at_100():
    sightings = [{"source": s, "hours_ago": 0} for s in ("otx", "virustotal")] * 50
    score, severity = compute_score(sightings)
    assert score == pytest.approx(100.0)
    assert severity == "critical"


@pytest.mark.parametrize(
    "score,expected",
    [
        (84.9, "high"),
        (85, "critical"),
        (64.9, "medium"),
        (65, "high"),
        (39.9, "low"),
        (40, "medium"),
        (14.9, "info"),
        (15, "low"),
        (0, "info"),
        (100, "critical"),
    ],
)
def test_severity_boundaries(score, expected):
    assert score_to_severity(score) == expected
