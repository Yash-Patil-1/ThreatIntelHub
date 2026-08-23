"""Shared async session factory for models/API code."""
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

SessionLocal = sessionmaker(bind=settings.database_url, expire_on_commit=False)
