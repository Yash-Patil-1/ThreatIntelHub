"""FastAPI entrypoint. Serves OpenAPI docs at /docs."""
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings
from app.core.security import hash_password
from app.models import User
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.iocs import router as iocs_router
from app.routers.settings import router as settings_router

logger = logging.getLogger(__name__)

app = FastAPI(title="ThreatIntelHub API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ponytail: engine created eagerly; pool sizing/tuning when load matters
engine = create_async_engine(settings.database_url)

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(iocs_router)
app.include_router(settings_router)


@app.on_event("startup")
async def seed_admin_on_first_boot():
    """First-boot admin: if users table is empty, seed from ADMIN_EMAIL/ADMIN_PASSWORD.

    Chosen over one-time setup token / forced-password-change flows — least code,
    matches BACKEND_SCHEMA §Auth model. Missing env → warn + skip per .env inventory.
    """
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not email or not password:
        logger.warning("ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping first-boot admin seed")
        return
    async with engine.begin() as conn:
        count = (await conn.execute(select(func.count()).select_from(User))).scalar()
        if count == 0:
            await conn.execute(
                User.__table__.insert().values(
                    email=email.lower(), password_hash=hash_password(password)
                )
            )
            logger.info("first-boot admin seeded: %s", email)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
