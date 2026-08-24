from functools import lru_cache
from os import environ


class Settings:
    """Env-backed settings. Required vars are validated at startup by later phases;
    scaffold reads with safe defaults so `docker compose up` works on day one."""

    database_url: str = environ.get("DATABASE_URL", "postgresql+asyncpg://tih:tih@pg:5432/tih")
    redis_url: str = environ.get("REDIS_URL", "redis://redis:6379/0")
    cors_origins: list[str] = [
        o.strip() for o in environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
    ]
    app_env: str = environ.get("APP_ENV", "production")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
