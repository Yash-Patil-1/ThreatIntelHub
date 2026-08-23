"""Seed: default admin placeholder + documented severity thresholds.

Run: python -m scripts.seed
"""
import asyncio
import os

from sqlalchemy import text

from app.core.db import SessionLocal
from app.models import User

# PROJECT_LOG.md decision 5: severity = critical ≥85 · high ≥65 · medium ≥40 · low ≥15 · info else.
SEVERITY_THRESHOLDS: dict[str, int] = {
    "critical": 85,
    "high": 65,
    "medium": 40,
    "low": 15,
}

# ponytail: no settings table in BACKEND_SCHEMA.md — thresholds live here as the
# single source of truth until a settings table is added; scorer should import this.


async def main() -> None:
    async with SessionLocal() as session:
        # ponytail: placeholder row only — auth-agent owns ADMIN_EMAIL/ADMIN_PASSWORD
        # seeding + argon2id hashing on first boot; password change forced-flow
        # triggers when hash equals the seed placeholder.
        email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
        existing = await session.execute(
            text("SELECT 1 FROM users WHERE email = :email"), {"email": email}
        )
        if not existing.scalar():
            session.add(User(email=email, password_hash="PLACEHOLDER_REPLACE_ON_FIRST_BOOT"))
            await session.commit()
        print(f"admin user ready: {email}")
        print(f"severity thresholds: {SEVERITY_THRESHOLDS} (info below {SEVERITY_THRESHOLDS['low']})")


if __name__ == "__main__":
    asyncio.run(main())
