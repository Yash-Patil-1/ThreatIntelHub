"""YARA rule generation from sample string extractions.

Samples store only sha256 + extracted strings (no raw bytes column), so
validation uses synthetic buffers built from the stored strings: the source
sample's buffer must match; buffers built from other samples must not (FP gate).
"""

import hashlib
import logging
import re

import yara as yara_lib
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Sample, YaraRule

log = logging.getLogger(__name__)

# printable ASCII runs of >=6 chars — cheap, deterministic extraction
STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
MAX_STRINGS_STORED = 200


def extract_strings(data: bytes) -> list[str]:
    """Longest-first, deduped, capped."""
    seen: dict[str, None] = {}
    for m in STRING_RE.finditer(data):
        s = m.group().decode("ascii")
        seen.setdefault(s, None)
    return sorted(seen, key=len, reverse=True)[:MAX_STRINGS_STORED]


def _pick_rule_strings(sample: Sample, other_samples: list[Sample], count: int = 5) -> list[str]:
    """Prefer long strings unique to this sample across the corpus."""
    others: set[str] = set()
    for s in other_samples:
        others.update(s.strings_extracted or [])
    candidates = [s for s in (sample.strings_extracted or []) if len(s) >= 8 and s not in others]
    if not candidates:
        candidates = [s for s in (sample.strings_extracted or []) if len(s) >= 8]
    # rarity first (unique), then length
    return sorted(candidates, key=lambda s: (s in others, -len(s)))[:count]


def build_rule(sample: Sample, picked: list[str]) -> str:
    name = "tih_" + re.sub(r"[^a-zA-Z0-9_]", "_", (sample.filename or "sample"))[:32]
    conds = " and ".join(f"$s{i}" for i in range(1, len(picked) + 1))
    lines = [f"rule {name}", "{"]
    lines.append('  meta:')
    lines.append(f'    author = "ThreatIntelHub auto-generator"')
    lines.append(f'    sample_sha256 = "{sample.sha256}"')
    lines.append('  strings:')
    for i, s in enumerate(picked, start=1):
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    $s{i} = "{esc}" ascii')
    lines.append('  condition:')
    lines.append(f'    {conds}')
    lines.append("}")
    return "\n".join(lines)


def _buffer(strings: list[str]) -> bytes:
    return ("\n".join(strings) * 3).encode("latin-1", errors="ignore")


async def generate_and_validate(db: AsyncSession, sample_id: str) -> YaraRule:
    """Pick strings -> build rule -> compile -> benign-corpus FP check -> persist."""
    sample = (await db.execute(select(Sample).where(Sample.id == sample_id))).scalar_one_or_none()
    if sample is None:
        raise LookupError("sample not found")
    others = (await db.execute(select(Sample).where(Sample.id != sample.id))).scalars().all()

    picked = _pick_rule_strings(sample, others)
    report_lines = []
    compiled = False
    fp_free = False
    rule_text = ""

    if not picked:
        report_lines.append("FAIL: no usable strings (need at least one string of length >= 8)")
    else:
        rule_text = build_rule(sample, picked)
        try:
            ruleset = yara_lib.compile(source=rule_text)
            compiled = True
            report_lines.append("compile: OK")
        except yara_lib.Error as exc:
            report_lines.append(f"compile: FAILED ({exc})")

        if compiled:
            src_buf = _buffer(sample.strings_extracted or picked)
            matches_src = bool(ruleset.match(data=src_buf))
            report_lines.append(f"matches source sample buffer: {matches_src}")
            fps = []
            for o in others:
                if ruleset.match(data=_buffer(o.strings_extracted or [])):
                    fps.append(o.filename or str(o.id))
            fp_free = not fps
            report_lines.append(
                f"benign corpus ({len(others)} samples): {'clean' if fp_free else 'FALSE POSITIVES: ' + ', '.join(fps)}"
            )
            if not matches_src:
                report_lines.append("WARN: rule does not match its own sample buffer")

    rule = YaraRule(
        sample_id=sample.id,
        name=(re.match(r"rule (\w+)", rule_text).group(1) if rule_text else f"tih_invalid_{hashlib.md5(str(now := __import__('datetime').datetime.now(timezone.utc)).encode()).hexdigest()[:8]}"),
        rule_text=rule_text,
        compiled=compiled,
        corpus_fp_free=fp_free,
        validation_report="\n".join(report_lines) or "no validation performed",
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule
