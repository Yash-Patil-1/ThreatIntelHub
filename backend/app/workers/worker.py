"""Worker entrypoint — APScheduler loop with Phase 2 ingestion jobs.

Jobs (cron from env, UTC):
  ingest_otx              — INGEST_OTX_CRON    default `0 * * * *`  (hourly)
  ingest_abuseipdb        — INGEST_AIPDB_CRON  default `0 3 * * *`  (daily 03:00)
  score_sweep             — SCORE_SWEEP_CRON   default `30 4 * * *` (nightly recompute)
VT/Shodan/InternetDB are strictly on-demand (lookup/enrichment) — never scheduled.
"""
import asyncio
import logging
import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("tih.worker")


def heartbeat():
    log.info("worker heartbeat")


def _cron(var: str, default: str) -> CronTrigger:
    return CronTrigger.from_crontab(os.environ.get(var, default))


async def main():
    from app.ingest.jobs import run_ingest_job

    async def otx_job():
        await run_ingest_job("otx")

    async def aipdb_job():
        await run_ingest_job("abuseipdb")

    async def score_sweep_job():
        from sqlalchemy import select

        from app.core.db import SessionLocal
        from app.models import Ioc
        from app.scoring.engine import recompute_for_ioc

        async with SessionLocal() as session:
            ioc_ids = (await session.execute(select(Ioc.id))).scalars().all()
            for ioc_id in ioc_ids:
                await recompute_for_ioc(session, ioc_id)
            await session.commit()
        log.info("score sweep finished (%d iocs)", len(ioc_ids))

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(heartbeat, "interval", seconds=60, id="heartbeat", max_instances=1)
    scheduler.add_job(otx_job, _cron("INGEST_OTX_CRON", "0 * * * *"),
                      id="ingest_otx", max_instances=1, coalesce=True)
    scheduler.add_job(aipdb_job, _cron("INGEST_AIPDB_CRON", "0 3 * * *"),
                      id="ingest_abuseipdb", max_instances=1, coalesce=True)
    scheduler.add_job(score_sweep_job, _cron("SCORE_SWEEP_CRON", "30 4 * * *"),
                      id="score_sweep", max_instances=1, coalesce=True)
    scheduler.start()
    log.info("worker scheduler started (ingest jobs: otx=%s abuseipdb=%s sweep=%s)",
             os.environ.get("INGEST_OTX_CRON", "0 * * * *"),
             os.environ.get("INGEST_AIPDB_CRON", "0 3 * * *"),
             os.environ.get("SCORE_SWEEP_CRON", "30 4 * * *"))
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
