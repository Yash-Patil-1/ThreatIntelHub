"""require_admin dependency — session-cookie auth for protected routes."""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import SESSION_COOKIE, hash_token
from app.models import Session as DbSession
from app.models import User


async def require_admin(
    request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    row = (
        await db.execute(select(DbSession).where(DbSession.token_hash == hash_token(token)))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    if row.expires_at <= datetime.now(timezone.utc):
        await db.delete(row)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    user = (await db.execute(select(User).where(User.id == UUID(str(row.user_id))))).scalar_one()
    return user
