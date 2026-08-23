# ThreatIntelHub

Self-hosted, lightweight threat intelligence platform for solo analysts and small teams.
It aggregates free OSINT feeds (AlienVault OTX, AbuseIPDB), correlates IOCs across sources
into a transparent 0–100 threat score, and outputs finished intelligence: dashboard,
maps/charts, exportable PDF/CSV/JSON/STIX reports, and a YARA rule generator.

## Features

- **Feed ingestion** — OTX pulses hourly, AbuseIPDB blacklist daily; VT/Shodan on-demand lookups only (free-tier friendly)
- **IOC correlation & scoring** — same IOC seen in multiple feeds scores higher; exponential age decay; severity tiers (critical/high/medium/low/info)
- **Dashboard** — KPI tiles, 14-day trend chart, world choropleth map, live refresh
- **IOC triage** — dense searchable list, ⌘K lookup palette, per-source score breakdown, enrichment tabs
- **Reports** — on-demand or scheduled daily digest in PDF/CSV/JSON/STIX 2.1
- **YARA Studio** — upload a sample, auto-generate a rarity-ranked rule, compile + false-positive validation gate, `.yar` export
- **Zero-key boot** — works with no API keys configured; add keys later via the Settings UI

## Quickstart

```bash
cp .env.example .env          # set ADMIN_EMAIL / ADMIN_PASSWORD
docker compose up -d --build
docker compose run --rm api alembic upgrade head   # first boot only
# open http://localhost:3000
```

Add provider API keys under **Settings → Feed Sources** (stored Fernet-encrypted), or via `.env`.
Without keys, scheduled feeds report `disabled` and everything else still works.

> **⚠️ VirusTotal non-commercial caveat**
> The VirusTotal *free* API tier is licensed for **non-commercial use only**
> (4 req/min, 500 req/day). Do not use it in a commercial deployment without
> VT's consent or a paid tier.

## Feed quotas (free tiers)

| Source | Free limits | Usage model |
|---|---|---|
| AlienVault OTX | unlimited-ish | hourly pulse pull |
| AbuseIPDB | 1000 checks/day, blacklist download 5/day | daily blacklist pull |
| VirusTotal | 4 req/min, 500/day — **non-commercial** | on-demand lookups |
| Shodan | host lookup free (~1/s); `/search` costs credits | on-demand host lookup; search disabled in v1 |

All outbound calls are cache-before-call with quota counters surfaced in the UI.

## Tech stack

| Layer | Choice |
|---|---|
| Backend | Python 3.12 · FastAPI · SQLAlchemy async · PostgreSQL 16 |
| Jobs | APScheduler worker (no Celery) · Redis rate-limiting/cache |
| Frontend | Next.js 14 · TypeScript · Tailwind · shadcn/ui · Tremor · react-simple-maps |
| Reports | WeasyPrint (PDF) · native STIX 2.1 JSON |
| Rules | yara-python |
| Deploy | Docker Compose — single host, <2 GB RAM target |

## License

[AGPL-3.0](./LICENSE). See also [SECURITY.md](./SECURITY.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
