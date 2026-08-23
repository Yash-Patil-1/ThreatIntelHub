import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
from app.models import AuditLog, Sample, YaraRule
from app.yaragen import generate_and_validate

router = APIRouter(prefix="/api/yara", tags=["yara"])
MAX_SAMPLE_BYTES = 10 * 1024 * 1024


@router.post("/samples", status_code=status.HTTP_201_CREATED)
async def upload_sample(
    file: UploadFile,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty file")
    if len(data) > MAX_SAMPLE_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "sample too large (max 10MB)")
    from app.yaragen import extract_strings

    sample = Sample(
        sha256=hashlib.sha256(data).hexdigest(),
        filename=file.filename or None,
        source_note=None,
        strings_extracted=extract_strings(data),
        uploaded_at=datetime.now(timezone.utc),
    )
    db.add(sample)
    await db.commit()
    await db.refresh(sample)
    return {"id": str(sample.id), "sha256": sample.sha256, "filename": sample.filename,
            "strings_extracted": len(sample.strings_extracted)}


@router.get("/samples")
async def list_samples(user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Sample).order_by(Sample.uploaded_at.desc()).limit(100))).scalars()
    return {"items": [{"id": str(s.id), "sha256": s.sha256, "filename": s.filename,
                       "strings_extracted": len(s.strings_extracted or []),
                       "uploaded_at": s.uploaded_at.isoformat()} for s in rows]}


@router.post("/rules/generate", status_code=status.HTTP_201_CREATED)
async def generate_rule(body_sample_id: dict, user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    sample_id = body_sample_id.get("sample_id")
    if not sample_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "sample_id required")
    try:
        rule = await generate_and_validate(db, sample_id)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found")
    return _rule_json(rule)


@router.get("/rules")
async def list_rules(user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(YaraRule).order_by(YaraRule.created_at.desc()).limit(100))).scalars()
    return {"items": [_rule_json(r) for r in rows]}


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return _rule_json(r)


@router.get("/rules/{rule_id}/export")
async def export_rule(rule_id: str, user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    db.add(AuditLog(action="export", entity_type="yara_rules", entity_id=str(r.id),
                    detail={"name": r.name}, at=datetime.now(timezone.utc)))
    await db.commit()
    return Response(content=r.rule_text.encode(), media_type="text/x-yara",
                    headers={"Content-Disposition": f'attachment; filename="{r.name}.yar"'})


def _rule_json(r: YaraRule) -> dict:
    return {
        "id": str(r.id), "sample_id": str(r.sample_id), "name": r.name,
        "rule_text": r.rule_text, "compiled": r.compiled, "corpus_fp_free": r.corpus_fp_free,
        "validation_report": r.validation_report, "created_at": r.created_at.isoformat(),
    }
