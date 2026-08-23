"""Settings API: provider API keys stored Fernet-encrypted, returned masked only."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
from app.core.security import encrypt_key, get_fernet, mask_key
from app.models import ApiKey, AuditLog, FeedSource

router = APIRouter(prefix="/api/settings", tags=["settings"])

PROVIDERS = ("otx", "virustotal", "abuseipdb", "shodan")


class KeyIn(BaseModel):
    provider: str
    api_key: str


@router.get("/api-keys")
async def list_api_keys(
    user: object = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    slugs = {fs.id: fs.slug for fs in (await db.execute(select(FeedSource))).scalars()}
    keys = {r.feed_source_id: r for r in (await db.execute(select(ApiKey))).scalars()}
    out = {}
    for slug in PROVIDERS:
        row = next((keys[fs_id] for fs_id, s in slugs.items() if s == slug), None)
        out[slug] = (
            {"configured": False, "hint": None}
            if row is None
            else {
                "configured": row.is_configured,
                "hint": row.key_hint,
                "validated_at": row.validated_at,
                "updated_at": row.updated_at,
            }
        )
    return out


@router.put("/api-keys")
async def set_api_key(
    body: KeyIn,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    slug = body.provider.lower()
    if slug not in PROVIDERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"provider must be one of {PROVIDERS}")
    if not body.api_key.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "api_key must not be empty")

    fs = (
        await db.execute(select(FeedSource).where(FeedSource.slug == slug))
    ).scalar_one_or_none()
    if fs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"feed source {slug!r} not found — run scripts/seed.py first")

    f = get_fernet()
    plaintext = body.api_key.strip()
    row = (
        await db.execute(select(ApiKey).where(ApiKey.feed_source_id == fs.id))
    ).scalar_one_or_none()
    if row is None:
        row = ApiKey(feed_source_id=fs.id)
        db.add(row)
    row.encrypted_key = encrypt_key(f, plaintext)
    row.key_hint = mask_key(plaintext)
    row.is_configured = True
    row.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(action="key_update", entity_type="api_keys", entity_id=slug, detail={"feed_source_id": fs.id}))
    await db.commit()
    return {"provider": slug, "configured": True, "hint": row.key_hint}


@router.delete("/api-keys/{provider}")
async def delete_api_key(
    provider: str,
    user: object = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    slug = provider.lower()
    if slug not in PROVIDERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"provider must be one of {PROVIDERS}")
    fs = (
        await db.execute(select(FeedSource).where(FeedSource.slug == slug))
    ).scalar_one_or_none()
    if fs is None or not (row := (await db.execute(select(ApiKey).where(ApiKey.feed_source_id == fs.id))).scalar_one_or_none()):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no key configured")
    await db.delete(row)
    db.add(AuditLog(action="key_delete", entity_type="api_keys", entity_id=slug))
    await db.commit()
    return {"provider": slug, "configured": False}
