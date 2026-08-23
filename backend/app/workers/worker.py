"""Worker entrypoint — APScheduler loop (stub jobs for now; feed ingest lands in Phase 2)."""
import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tih.worker")


def heartbeat():
    log.info("worker heartbeat")


async def main():
    scheduler = AsyncIOScheduler()
    scheduler.add_job(heartbeat, "interval", seconds=60, id="heartbeat", max_instances=1)
    scheduler.start()
    log.info("worker scheduler started")
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
