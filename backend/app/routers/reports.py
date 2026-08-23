import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
from app.models import AuditLog, Report, ReportArtifact
from app.reports.generator import FORMATS

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])

CONTENT_TYPES = {
    "pdf": "application/pdf",
    "csv": "text/csv",
    "json": "application/json",
    "stix": "application/stix+json",
}


class ReportIn(BaseModel):
    kind: str = "ondemand"
    limit: int = 100


async def _run_generation(report_id: str) -> None:
    from app.core.db import SessionLocal
    from app.reports.generator import complete_report

    async with SessionLocal() as session:
        report = (await session.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
        if report is None:
            return
        await complete_report(session, report)


@router.get("")
async def list_reports(user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Report).order_by(Report.created_at.desc()).limit(100))).scalars()
    out = []
    for r in rows:
        arts = (await db.execute(select(ReportArtifact).where(ReportArtifact.report_id == r.id))).scalars()
        out.append({
            "id": str(r.id), "kind": r.kind, "status": r.status,
            "period_start": r.period_start.isoformat(), "period_end": r.period_end.isoformat(),
            "created_at": r.created_at.isoformat(), "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "artifacts": [{"id": a.id, "format": a.format, "size_bytes": a.size_bytes} for a in arts],
        })
    return {"items": out}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_report(
    body: ReportIn,
    background: BackgroundTasks,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if body.kind not in ("daily", "weekly", "ondemand"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "kind must be daily|weekly|ondemand")
    report = Report(kind=body.kind, period_start=datetime.now(timezone.utc),
                    period_end=datetime.now(timezone.utc), status="pending")
    db.add(report)
    await db.commit()
    background.add_task(_run_generation, str(report.id))
    return {"id": str(report.id), "status": "pending"}


@router.get("/{report_id}")
async def get_report(report_id: str, user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    arts = (await db.execute(select(ReportArtifact).where(ReportArtifact.report_id == r.id))).scalars()
    return {
        "id": str(r.id), "kind": r.kind, "status": r.status,
        "period_start": r.period_start.isoformat(), "period_end": r.period_end.isoformat(),
        "created_at": r.created_at.isoformat(), "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "artifacts": [{"id": a.id, "format": a.format, "size_bytes": a.size_bytes} for a in arts],
        "formats_available": list(FORMATS),
    }


@router.get("/{report_id}/artifacts/{artifact_id}/download")
async def download_artifact(
    report_id: str, artifact_id: int,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    a = (await db.execute(select(ReportArtifact).where(
        ReportArtifact.id == artifact_id, ReportArtifact.report_id == report_id))).scalar_one_or_none()
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Artifact not found")
    try:
        data = open(a.file_path, "rb").read()
    except OSError:
        raise HTTPException(status.HTTP_410_GONE, "Artifact file missing on disk")
    db.add(AuditLog(action="export", entity_type="reports", entity_id=f"{report_id}/{a.format}",
                    detail={"artifact_id": artifact_id}, at=datetime.now(timezone.utc)))
    await db.commit()
    fname = f"threatintelhub-report.{a.format}"
    return Response(content=data, media_type=CONTENT_TYPES[a.format],
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(report_id: str, user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    arts = (await db.execute(select(ReportArtifact).where(ReportArtifact.report_id == r.id))).scalars()
    for a in arts:
        try:
            import os
            os.unlink(a.file_path)
        except OSError:
            pass
        await db.delete(a)
    await db.delete(r)
    await db.commit()
