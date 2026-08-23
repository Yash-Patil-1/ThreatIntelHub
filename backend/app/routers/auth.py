"""Auth endpoints: login/logout/me. Single-admin, session-cookie auth."""
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import require_admin
from app.core.security import (
    SESSION_COOKIE,
    SESSION_TTL,
    clear_failed_logins,
    hash_token,
    is_locked,
    new_session_token,
    record_failed_login,
    verify_password,
)
from app.models import AuditLog
from app.models import Session as DbSession
from app.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
async def login(body: LoginIn, response: Response, db: AsyncSession = Depends(get_db)):
    email = body.email.lower()
    if is_locked(email):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts; try again later")

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or not verify_password(user.password_hash, body.password):
        record_failed_login(email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    clear_failed_logins(email)
    token, token_hash = new_session_token()
    expires_at = datetime.now(timezone.utc) + SESSION_TTL
    db.add(DbSession(user_id=user.id, token_hash=token_hash, expires_at=expires_at))
    db.add(AuditLog(action="login", entity_type="users", entity_id=str(user.id), detail={"email": email}))
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=os.environ.get("APP_ENV", "production") != "development",
        samesite="lax",
    )
    return {"id": str(user.id), "email": user.email}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await db.execute(delete(DbSession).where(DbSession.token_hash == hash_token(token)))
        await db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/me")
async def me(user: User = Depends(require_admin)):
    return {"id": str(user.id), "email": user.email, "last_login_at": user.last_login_at}
