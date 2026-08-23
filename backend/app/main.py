"""FastAPI entrypoint. Serves OpenAPI docs at /docs."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings

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


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
