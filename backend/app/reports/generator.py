"""Report generation: Jinja2 template -> WeasyPrint PDF + CSV/JSON/STIX artifacts.

Artifacts are written to disk under DATA_DIR/reports/{report_id}/ (the
report_artifacts.file_path column stores the path). Small files, single host.
"""

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Ioc, Report, ReportArtifact

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
DATA_DIR = Path(__import__("os").environ.get("DATA_DIR", "/app/data")) / "reports"


async def _top_iocs(db: AsyncSession, limit: int) -> list[dict]:
    rows = (
        await db.execute(
            select(Ioc).order_by(Ioc.threat_score.desc(), Ioc.last_seen.desc()).limit(limit)
        )
    ).scalars()
    return [
        {
            "threat_score": r.threat_score,
            "severity": r.severity,
            "type": r.type,
            "value_norm": r.value_norm,
            "last_seen": r.last_seen.strftime("%Y-%m-%d %H:%M UTC"),
        }
        for r in rows
    ]


def _stix_pattern(itype: str, value: str) -> str | None:
    if itype == "ip":
        obj = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{obj}:value = '{value}']"
    if itype == "domain":
        return f"[domain-name:value = '{value}']"
    if itype == "url":
        return f"[url:value = '{value}']"
    if itype in ("sha256", "sha1", "md5"):
        algo = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[itype]
        return f"[file:hashes.'{algo}' = '{value}']"
    return None


def _stix_bundle(iocs: list[dict], period_start: datetime) -> dict:
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--d5c6b0a5-9e3a-4f8a-b1c2-threatintehub",
        "name": "ThreatIntelHub",
        "identity_class": "system",
    }]
    for i in iocs:
        pat = _stix_pattern(i["type"], i["value_norm"])
        if not pat:
            continue
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            # ponytail: deterministic UUIDv5-style id not needed for v1; STIX ids must be unique per object only here
            "id": f"indicator--{abs(hash((i['type'], i['value_norm']))) & 0xffffffffffffffff:032x}",
            "created_by_ref": "identity--d5c6b0a5-9e3a-4f8a-b1c2-threatintehub",
            "created": period_start.isoformat().replace("+00:00", "Z"),
            "modified": period_start.isoformat().replace("+00:00", "Z"),
            "pattern_type": "stix",
            "pattern": pat,
            "valid_from": period_start.isoformat().replace("+00:00", "Z"),
            "labels": [i["severity"]],
            "confidence": i["threat_score"],
        })
    return {"type": "bundle", "id": "bundle--" + period_start.strftime("%Y%m%d%H%M%S"), "objects": objects}


def _artifact_bytes(fmt: str, iocs: list[dict], kpis: dict, meta: dict) -> bytes:
    if fmt == "json":
        return json.dumps({"meta": meta, "kpis": kpis, "iocs": iocs}, indent=2, default=str).encode()
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["threat_score", "severity", "type", "value_norm", "sources", "last_seen"])
        w.writeheader()
        for i in iocs:
            w.writerow({**i, "sources": ",".join(i.get("sources", []))})
        return buf.getvalue().encode()
    if fmt == "stix":
        return json.dumps(_stix_bundle(iocs, meta["period_start"]), indent=2).encode()
    if fmt == "pdf":
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        html = env.get_template("report.html.j2").render(
            kind=meta["kind"],
            period_start=meta["period_str"],
            period_end=meta["period_end"].strftime("%Y-%m-%d %H:%M UTC"),
            generated_at=meta["generated_at"].strftime("%Y-%m-%d %H:%M UTC"),
            kpis=kpis,
            iocs=iocs,
        )
        from weasyprint import HTML as WHTML

        return WHTML(string=html).write_pdf()
    raise ValueError(f"unknown format {fmt}")  # pragma: no cover


FORMATS = ("pdf", "csv", "json", "stix")


async def generate_report(db: AsyncSession, kind: str = "ondemand", limit: int = 100) -> Report:
    """Create + fill a report (used by the daily cron). Never raises."""
    now = datetime.now(timezone.utc)
    report = Report(kind=kind, period_start=now - timedelta(days=1), period_end=now, status="generating")
    db.add(report)
    await db.commit()
    return await complete_report(db, report, limit=limit)


async def complete_report(db: AsyncSession, report: Report, limit: int = 100) -> Report:
    """Fill an existing (pending/generating) report row through ready|failed."""
    now = datetime.now(timezone.utc)
    period_start = report.period_start
    if report.status == "pending":
        report.status = "generating"
        await db.commit()
    try:
        kpi_rows = (await db.execute(select(Ioc.severity, func.count()).group_by(Ioc.severity))).all()
        by_sev = {sev: n for sev, n in kpi_rows}
        kpis = {
            "total_iocs": sum(by_sev.values()),
            **{s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        }
        iocs = await _top_iocs(db, limit)
        out_dir = DATA_DIR / str(report.id)
        out_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "kind": report.kind,
            "period_start": period_start,
            "period_end": now,
            "period_str": period_start.strftime("%Y-%m-%d %H:%M UTC"),
            "generated_at": now,
        }
        for fmt in FORMATS:
            data = _artifact_bytes(fmt, iocs, kpis, meta)
            path = out_dir / f"report.{fmt}"
            path.write_bytes(data)
            db.add(ReportArtifact(report_id=report.id, format=fmt, file_path=str(path), size_bytes=len(data)))
        report.status = "ready"
    except Exception:  # noqa: BLE001 — failure recorded on the row, never raised (worker-safe)
        log.exception("report generation failed")
        report.status = "failed"
        report.completed_at = now
        await db.commit()
        return report
    report.completed_at = datetime.now(timezone.utc)
    await db.commit()
    return report
