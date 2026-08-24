# Backend Schema — ThreatIntelHub

> Open-source edition (AGPL-3.0). All external APIs are free-tier only; users bring their own keys via `.env` (see [`.env` inventory](#env-variable-inventory)). Free quotas drive every TTL/rate-limit decision below — see RESEARCH_NOTES.md §API facts for verified numbers.

## Data model

```mermaid
erDiagram
    users ||--o{ sessions : has
    users ||--o{ audit_log : performs
    feed_sources ||--o{ feed_health : monitored_by
    feed_sources ||--o{ quota_usage : metered_in
    feed_sources ||--o{ sightings : produces
    feed_sources ||--o{ enrichments : provides
    feed_sources ||--o{ api_keys : configured_with
    iocs ||--o{ sightings : has
    iocs ||--o{ enrichments : has
    iocs ||--o{ report_items : appears_in
    reports ||--o{ report_items : contains
    reports ||--o{ report_artifacts : exports_as
    samples ||--o{ yara_rules : generates
    yara_rules ||--o{ yara_rule_iocs : references
    iocs ||--o{ yara_rule_iocs : referenced_by

    users {
        uuid id PK "gen_random_uuid()"
        text email UK "lowercased"
        text password_hash "argon2id"
        timestamptz created_at "now()"
        timestamptz last_login_at NULL
    }
    sessions {
        uuid id PK
        int user_id FK
        text token_hash UK "sha256 of cookie value"
        timestamptz expires_at "now()+24h"
        timestamptz created_at
    }
    feed_sources {
        int id PK
        text slug UK "otx|virustotal|abuseipdb|shodan"
        text display_name
        numeric reliability_weight "0.0-1.0, e.g. VT=1.0"
        bool enabled "true"
        jsonb schedule_cron "per-feed cron config"
        jsonb cursor_state "pagination cursor per feed"
    }
    feed_health {
        int id PK
        int feed_source_id FK "UNIQUE(feed_source_id)"
        timestamptz last_success_at NULL
        timestamptz last_attempt_at NULL
        text last_status "ok|degraded|quota_exhausted|error|disabled"
        text last_error NULL "truncated to 500 chars"
        int consecutive_failures "0"
        int items_last_run "IOCs inserted last run"
        float duration_ms_last_run NULL
        timestamptz updated_at "touch every run"
    }
    quota_usage {
        int id PK
        int feed_source_id FK
        date day UK_together "UNIQUE(feed_source_id, day) UTC day"
        int calls_made "0"
        int calls_limit "from RESEARCH_NOTES quotas"
        int quota_violations "0 — should stay 0; >0 is a bug alert"
    }
    iocs {
        bigint id PK
        text type "ip|domain|url|sha256|sha1|md5 CHECK constraint"
        text value_norm "UNIQUE(type,value_norm); lowercased, url-decoded, IPs canonicalized"
        int threat_score "0-100, default 0 until scored"
        text severity "critical|high|medium|low|info default info"
        timestamptz first_seen
        timestamptz last_seen
        bool is_stale "false; set when no sighting in 90d"
        jsonb tags NULL "e.g. ["ransomware","apt"] from pulse names"
        timestamptz score_computed_at "staleness guard for UI"
    }
    sightings {
        bigint id PK
        bigint ioc_id FK
        int feed_source_id FK
        text external_ref "source-native ID (pulse id, VT id)"
        timestamptz seen_at
        jsonb raw "raw payload excerpt, capped 16KB"
        timestamptz ingested_at "now()"
    }
    enrichments {
        bigint id PK
        bigint ioc_id FK
        int feed_source_id FK "UNIQUE(ioc_id,feed_source_id)"
        jsonb data "normalized per-feed payload"
        timestamptz fetched_at
        timestamptz expires_at "TTL per source, see Redis schema"
    }
    reports {
        uuid id PK
        text kind "daily|weekly|ondemand"
        timestamptz period_start
        timestamptz period_end
        text status "pending|generating|ready|failed"
        timestamptz created_at
        timestamptz completed_at NULL
    }
    report_items {
        bigint id PK
        uuid report_id FK
        bigint ioc_id FK "UNIQUE(report_id,ioc_id)"
        text reason "top_score|new_today|multi_source|watchlist"
        int score_at_generation "snapshot"
    }
    report_artifacts {
        bigint id PK
        uuid report_id FK
        text format "pdf|json|csv|stix CHECK"
        text file_path "under DATA_DIR/reports/, relative"
        bigint size_bytes NULL
        timestamptz created_at
    }
    api_keys {
        int id PK
        int feed_source_id FK "UNIQUE(feed_source_id)"
        bytea encrypted_key "Fernet, master key = env MASTER_KEY"
        text key_hint "last 4 chars for masked UI display"
        bool is_configured "false until a key saved"
        timestamptz validated_at NULL "last successful test ping"
        timestamptz updated_at
    }
    samples {
        uuid id PK
        text sha256 UK "dedupe key; file itself stored under DATA_DIR/samples/"
        text filename NULL
        text source_note NULL "analyst context"
        jsonb strings_extracted "rarity-ranked string list"
        timestamptz uploaded_at
    }
    yara_rules {
        uuid id PK
        uuid sample_id FK
        text name UK "rule:<sha256[:8]>_<seq>"
        text rule_text "full YARA source"
        bool compiled "yara-python compile ok"
        bool corpus_fp_free "passed benign-corpus scan"
        text validation_report NULL "JSON blob of match results"
        timestamptz created_at
    }
    yara_rule_iocs {
        bigint id PK
        uuid yara_rule_id FK
        bigint ioc_id FK "UNIQUE(yara_rule_id,ioc_id)"
        text role "derived_from|related"
    }
    audit_log {
        bigint id PK
        int user_id FK NULL
        text action "login|export|key_update|report_generate|..."
        text entity_type NULL "iocs|reports|api_keys|..."
        text entity_id NULL
        jsonb detail NULL
        inet ip_address NULL
        timestamptz at
    }
```

Notes carried from v0 draft, now explicit:
- **Sightings dedupe**: `UNIQUE (ioc_id, feed_source_id, external_ref)`; re-ingests hit this constraint and become no-ops (`ON CONFLICT DO NOTHING`) — this is what makes dedupe rate >95%.
- **Enrichments**: one row per `(ioc, source)`; refetch overwrites `data` and bumps `fetched_at`/`expires_at`.
- **Quota usage is persisted** (not just Redis) so the settings page survives Redis restarts; Redis holds the *live* counters, Postgres holds the *daily rollup* written at job end.

## Key fields & indexes

| Table | Index | Rationale |
|---|---|---|
| `iocs` | `UNIQUE (type, value_norm)` | The dedupe/correlation key — everything routes through it. |
| `iocs` | `(severity, threat_score DESC, last_seen DESC)` | Dashboard/list default sort: worst-first triage queue. Single composite covers filter+sort+cursor. |
| `iocs` | GIN on `tags` | Tag filtering without a join table (tags are advisory metadata, not relational). |
| `iocs` | `(is_stale) WHERE is_stale` | Partial index; stale-sweep finds its victims instantly, index stays tiny. |
| `sightings` | `(ioc_id, seen_at DESC)` | Timeline tab on IOC detail. |
| `sightings` | `(seen_at)` monthly-brute-force scan instead of partitions for MVP | Partitioning deferred (TRD); revisit at 50K IOCs/day load pass. |
| `enrichments` | `(expires_at)` | TTL sweeper job picks expired rows cheaply. |
| `audit_log` | `(at DESC)` | Recent-actions view; also the export-compliance trail. |
| `sessions` | `(token_hash)` via UNIQUE + `(expires_at)` for cleanup sweep | Login lookup is the hot path; expired-session GC needs the second. |
| `quota_usage` | `UNIQUE (feed_source_id, day)` | Idempotent daily upsert from worker. |
| `report_items` | `UNIQUE (report_id, ioc_id)` | Regeneration is idempotent. |

## Scoring formula (transparent, shown in UI)

```
score = min(100, round(
    Σ_per_source (reliability_weight × age_decay(last_seen))   # OTX .8, VT 1.0, AbuseIPDB .9, Shodan .6
  + cross_source_bonus(n_sources)                              # +15 if ≥2, +25 if ≥3
  + sighting_bonus(log2(1+n_sightings_30d) × 5)
))
age_decay(t) = exp(-hours_since / 720)   # ~30-day half-life-ish
severity = critical ≥85 · high ≥65 · medium ≥40 · low ≥15 · info else
```

### Recomputation trigger points

Scores are stored denormalized and recomputed **on events only** — never per request. Exact trigger map:

| # | Event | Trigger site | Scope | Timing |
|---|---|---|---|---|
| T1 | New `sightings` row inserted (post-dedupe) | Ingestion pipeline, after `ON CONFLICT` commit | That single `ioc_id` | Synchronous, same transaction boundary (after commit, queued inline) |
| T2 | New `enrichments` row / enrichment refresh | On-demand enrichment pipeline (lookup button) + scheduled enrichment refresh | That `ioc_id`; if enrichment adds a *new source* presence, also bumps cross-source term | Synchronous |
| T3 | Nightly age-decay sweep | APScheduler cron `0 3 * * *` | All non-stale IOCs whose `score_computed_at < now()-24h` (batched 5K/chunk) | Async batch job |
| T4 | Stale sweep marks `is_stale=true` | Same nightly job, IOCs silent >90 days | Batch | Same job as T3 |
| T5 | Admin edits `reliability_weight` or disables a feed | Settings PUT handler | All IOCs seen by that source (enqueue chunked background rescore) | Async, progress surfaced in feed_health |
| T6 | Dedupe merge (two IOC rows collapse) | Normalizer when normalization changes an existing value's type class | Merged survivor row | Synchronous |

Rule: **T1/T2/T6 recompute inline (single-row, ~ms)**; T3/T4/T5 run through a `rescore_queue` Redis list consumed by the worker so HTTP handlers never block on bulk math. Every recompute updates `threat_score`, `severity`, and `score_computed_at` together.

## Auth model (v1: single admin)

- Session-cookie auth; argon2id password hash; `sessions` table w/ expiry (24h sliding).
- Initial admin seeded from env (`ADMIN_EMAIL`/`ADMIN_PASSWORD`) on first boot; password change forced-flow if hash equals the seed placeholder.
- API keys encrypted at rest (Fernet, master key from env `MASTER_KEY`); decrypted only in worker memory, never serialized into logs or API responses (masked hint only).
- All exports and key mutations logged to `audit_log`.

## Redis key schema

Free-tier quotas make caching non-negotiable: **cache-before-call** — every adapter checks Redis before any outbound request. Keys are prefixed `tih:` for namespace safety on shared Redis instances.

### Cache keys

| Pattern | Value | TTL | Rationale |
|---|---|---|---|
| `tih:ench:{source}:{ioc_hash}` | JSON normalized enrichment | **VT 24h**, AbuseIPDB 12h, Shodan 6h, InternetDB 6h, OTX 12h | Sized to burn minimum daily quota on repeat lookups. VT's 500/day cap means a 24h TTL is the difference between working and dead by noon under normal analyst traffic. |
| `tih:score:{ioc_id}` | Final computed score+severity snapshot | 300s | Absorbs duplicate dashboard reads between recomputes; DB row remains source of truth. |
| `tih:dash:summary` | Pre-aggregated KPI/trend/map payload | 60s | Dashboard polls; recomputing aggregates per poll would hammer PG. |
| `tih:otx:pulse:{id}` | Seen-pulse marker | 30d | Skip re-pulling pulses already fully processed. |
| `tih:yara:corpus_hashes` | Set of benign-sample hashes | no TTL | Validation-loop membership check. |

### Rate-limit counters (token buckets / fixed windows)

| Pattern | Semantics | Reset |
|---|---|---|
| `tih:rl:vt:min` | INCR counter + 60s expiry → enforce ≤4/min | rolling minute window |
| `tih:rl:vt:day` | INCR counter, expiry at next UTC midnight → enforce ≤500/day | daily |
| `tih:rl:aipdb:day` | INCR, daily expiry → ≤1000 checks/day | daily |
| `tih:rl:aipdb:blacklist` | INCR, daily expiry → ≤5 blacklist pulls/day | daily |
| `tih:rl:shodan:host` | Sliding-window (sorted set of timestamps) → ~1 req/s | pruned continuously |
| `tih:rl:internetdb` | Fixed 10/min courtesy limit (unauth API, be polite) | minute window |
| `tih:bucket:{source}` | Token-bucket state (tokens, last_refill) used by the limiter middleware | n/a |

Limiter behavior on exhaustion: raise typed `QuotaExhaustedError` → adapter returns cached data if any exists, else surfaces `quota_exhausted` status to `feed_health`; **never** queues retries past quota reset silently.

## REST surface (v1)

All endpoints cookie-authenticated except `/api/auth/login`. Errors use `{"detail": "<msg>"}` (FastAPI convention) with proper status codes: 401 unauth, 409 conflict, 422 validation, 429 upstream-quota-exhausted relayed.

### Auth

```http
POST /api/auth/login
{"email": "admin@example.com", "password": "••••••"}
→ 200 {"id": "…", "email": "admin@example.com"}   # sets HttpOnly session cookie
→ 401 {"detail": "Invalid credentials"}

POST /api/auth/logout   → 204
```

### IOCs

```http
GET /api/iocs?type=ip&severity=critical&q=185.&cursor=eyJvZmZzZXQiOjUwfQ&limit=50
→ 200 {
  "items": [{
    "id": 1042, "type": "ip", "value_norm": "185.220.101.45",
    "threat_score": 91, "severity": "critical",
    "sources": ["virustotal","abuseipdb"],          // denormalized for list view
    "first_seen": "2026-08-20T04:11:02Z",
    "last_seen": "2026-08-23T01:44:19Z"
  }],
  "next_cursor": "eyJvZmZzZXQiOjEwMH0=",            // null = end
  "total_estimate": 12847                            // approximate, cheap count
}

GET /api/iocs/1042
→ 200 { …list item… , "tags": [...], "sightings_count": 37,
        "score_breakdown": {"per_source": {...}, "cross_source_bonus": 25,
                            "sighting_bonus": 15, "formula_version": 1},
        "score_computed_at": "…" }

POST /api/iocs/lookup          # ⌘K find-or-enrich
{"value": "evil.example.com"}
→ 200 {"ioc": {...}, "cache_hit": true}                       # served from Redis/DB
→ 202 {"ioc_id": 1042, "job": "enrich"}                        # cold: async enrichment started; poll GET /api/iocs/{id}
→ 400 {"detail": "Unrecognized indicator format"}
```

Lookup policy: normalize → return existing within TTL → else trigger on-demand enrichment honoring rate-limit counters (VT/Shodan spend quota here).

### Dashboard

```http
GET /api/dashboard/summary
→ 200 {"kpis": {"total_iocs": 12847, "critical_today": 14, "new_24h": 812,
                "feeds_ok": 3, "feeds_total": 4},
       "trend": [{"day":"2026-08-17","new":640,"critical":9}, ...],
       "map": [{"country":"RU","count":2143}, ...],
       "generated_at": "2026-08-23T09:00:00Z"}
```

### Reports

```http
GET  /api/reports?kind=daily&limit=20
POST /api/reports/generate
{"kind": "ondemand", "period_start": "2026-08-22T00:00:00Z", "period_end": "2026-08-23T00:00:00Z"}
→ 202 {"id": "7c9e…", "status": "pending"}      # poll GET /api/reports/{id}

GET /api/reports/{id}
GET /api/reports/{id}/file?format=pdf            # streams artifact; logged to audit_log
→ 404 if not ready; → 409 while generating
```

### YARA

```http
POST /api/yara/generate
{"sample_sha256": "d41d…", "min_rarity": 3}
→ 201 {"id": "…", "name": "rule:d41d8cd9_1", "compiled": true,
       "corpus_fp_free": false}                   # false until validate passes

POST /api/yara/{id}/validate
{"corpus_dir": null}                              # null = bundled benign corpus
→ 200 {"validated": true, "benign_matches": 0, "sample_matches": 1}

GET /api/yara?validated=true&limit=50
GET /api/yara/{id}/export                         # downloads .yar
```

### Settings / feeds

```http
GET /api/settings/feeds
→ 200 [{"slug": "virustotal", "enabled": true, "reliability_weight": 1.0,
        "schedule_cron": null,                    // null = on-demand-only source
        "key_configured": true, "key_hint": "…a41f",
        "health": {"last_status": "ok", "last_success_at": "…"},
        "quota": {"day": "2026-08-23", "calls_made": 212, "calls_limit": 500}}]

PUT /api/settings/feeds/virustotal
{"enabled": true, "reliability_weight": 1.0}
PUT /api/settings/feeds/virustotal/key
{"api_key": "sk-or-v1-…"}                          # Fernet-encrypted immediately; response never echoes it
POST /api/settings/feeds/{slug}/test               # 1-call ping, records validated_at
→ 200 {"ok": true, "latency_ms": 340}  |  → 200 {"ok": false, "error": "401 invalid key"}
```

## .env variable inventory

Single source of truth for configuration. Users copy `.env.example` → `.env` and fill what they have. **The app boots with zero keys** — zero-key sources (Shodan InternetDB/CVEDB) still function; keyed sources show `disabled` in health until configured.

### Required

| Var | Example | Used by | Missing behavior |
|---|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://tih:tih@pg:5432/tih` | api, worker | hard fail at startup |
| `REDIS_URL` | `redis://redis:6379/0` | api, worker | hard fail at startup |
| `MASTER_KEY` | 32-byte urlsafe base64 | api (encrypt/decrypt keys) | hard fail — refuse to boot rather than store keys plaintext |
| `SECRET_KEY` | random 64 hex | session cookie signing | hard fail |
| `ADMIN_EMAIL` | `admin@example.com` | first-boot admin seed | warn + skip seeding |
| `ADMIN_PASSWORD` | strong password | first-boot admin seed | warn + skip seeding |

### Optional — per-source API keys (free tiers)

| Var | Source | Free limits (RESEARCH_NOTES.md) | Missing behavior |
|---|---|---|---|
| `OTX_API_KEY` | AlienVault OTX | free account, generous | feed disabled, health=`disabled`; UI shows setup hint |
| `VIRUSTOTAL_API_KEY` | VirusTotal | 4/min, 500/day, **non-commercial** | on-demand lookups skip VT tab; README states non-commercial restriction prominently |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1000 checks/day, 5 blacklist/day | blacklist ingest disabled; per-check enrichment skipped |
| `SHODAN_API_KEY` | Shodan | host lookup free (~1 req/s); search costs credits — **we never call search** | host-enrichment skipped; InternetDB fallback still runs |

### Optional — tuning / ops

| Var | Default | Notes |
|---|---|---|
| `APP_ENV` | `production` | `development` enables verbose errors + SQL echo |
| `LOG_LEVEL` | `INFO` | |
| `TZ` | `UTC` | all scheduling/cursor windows are UTC regardless |
| `CORS_ORIGINS` | `http://localhost:3000` | comma-separated |
| `DATA_DIR` | `/data` | samples, report artifacts, benign YARA corpus mount |
| `INGEST_OTX_CRON` | `0 * * * *` | hourly pulse pull |
| `INGEST_AIPDB_CRON` | `0 4 * * *` | daily blacklist pull (off-peak) |
| `RESCORE_SWEEP_CRON` | `0 3 * * *` | nightly decay/stale sweep (scoring T3/T4) |
| `REPORT_DAILY_CRON` | `30 6 * * *` | daily digest generation |
| `ENRICH_TTL_VT_HOURS` etc. | see Redis table | escape hatches; defaults already quota-safe |

Graceful-degradation contract: **no optional key ever blocks boot or breaks another feature**. Each missing key only dims its own slice of the UI, with a one-line "add `VARNAME` to `.env`" hint.
