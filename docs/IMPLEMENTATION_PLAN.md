# Implementation Plan — ThreatIntelHub

> **Execution directive (user, 2026-08-23):** All implementation phases use **specialized subagents and installed skills**. Phase 1 leads orchestrate via `team_spawn`/task board; each phase names the skills/subagents to dispatch. No phase runs as a single monolithic session.

## MVP cut line

**MVP = Phases 1–4 + the Phase 5 open-source release prep marked [MVP].** Anything in PRD "Should/Could" not listed below is deferred to post-MVP (Phase 6+). Tasks inside phases are tagged `[MVP]` or `[post-MVP]` — if a task lacks a tag it is MVP by default.

Effort scale per task: **S** ≤ half day · **M** ~1 day · **L** 2+ days.

## Phases

### Phase 1 — Skeleton & data core (Week 1)

**Orchestration:** lead agent coordinates three subagents in sequence with review gates:
- `scaffold-agent` (skills: project-kickoff conventions, ponytail for minimalism)
- `schema-agent` (skills: postgres, dignified-python)
- `auth-agent` (skills: code-security, dignified-python)

Tasks:
- [ ] **1.1 [M]** Repo scaffold: `backend/` (FastAPI, SQLAlchemy async 2.x, alembic) + `frontend/` (Next.js 14, shadcn init, Tremor install) + docker-compose (`api`/`worker`/`pg`/`redis`/`web`) — *deps: none* — **done when**: `docker compose up` starts all five services healthy; `/docs` serves OpenAPI; Next dev server renders default page.
- [ ] **1.2 [S]** `.env.example` with every var from BACKEND_SCHEMA.md §.env inventory + `.gitignore` covering `.env`, `PROJECT_LOG.md`, `DATA_DIR/` — *deps: none* — **done when**: fresh clone boots from `.env.example` alone; `git status --ignored` shows secrets ignored.
- [ ] **1.3 [L]** Schema migration: all tables from BACKEND_SCHEMA.md incl. new ones (`feed_health`, `quota_usage`, `report_artifacts`) with every index/constraint listed there — *deps: 1.1* — **done when**: `alembic upgrade head` applies cleanly on empty PG; unique constraints verified by attempting duplicate inserts.
- [ ] **1.4 [S]** Seed script: `feed_sources` rows ×4 with reliability weights + schedules; first-boot admin from env — *deps: 1.3* — **done when**: re-running seed is idempotent; admin can log in after fresh DB.
- [ ] **1.5 [M]** Auth: login/logout endpoints, session cookie (HttpOnly, SameSite=Lax), argon2id hashing, session expiry middleware — *deps: 1.3* — **done when**: login sets cookie, logout clears it, expired session returns 401, password never stored in plaintext anywhere (grep-verified).
- [ ] **1.6 [M]** Settings API: store API keys Fernet-encrypted (`MASTER_KEY`), masked hints, test-key ping endpoint per feed — *deps: 1.4, 1.5* — **done when**: key round-trips through encrypt→decrypt in worker memory only; API response contains hint but never full key; ping reports ok/error per source.
- [ ] **1.7 [S]** Settings page shell (frontend): feed cards with masked keys, enable toggle, weight field — *deps: 1.6* — **done when**: saving a key persists across page reload and container restart.

- **Done when**: login works; keys saved encrypted; compose up runs all services.

### Phase 2 — Ingestion & correlation (Week 2)

**Orchestration:** `ingest-agent` (skills: dignified-python, systematic-debugging) builds adapters; `scoring-agent` (skills: dignified-python) builds engine; both reviewed by `security-review` pass on trust-boundary handling of raw payloads.

Tasks:
- [ ] **2.1 [L]** Rate-limit middleware: shared token-bucket/fixed-window limiter over Redis keys from BACKEND_SCHEMA.md §Redis schema — *deps: 1.3* — **done when**: unit test drives a fake clock past VT's 4/min limit and 5th call raises `QuotaExhaustedError`; counters survive Redis restart via daily-rollup write-back.
- [ ] **2.2 [L]** Feed adapters ×4 (OTX pulse pull, AbuseIPDB blacklist + check, Shodan host lookup + InternetDB/CVEDB zero-key enrichment), each wrapped cache-before-call — *deps: 2.1* — **done when**: recorded-fixture tests pass for all four; no adapter makes an outbound call without checking `tih:ench:*` first (verified by counting mock HTTP calls).
- [ ] **2.3 [M]** APScheduler jobs: OTX hourly (`INGEST_OTX_CRON`), AbuseIPDB blacklist daily (`INGEST_AIPDB_CRON`); VT/Shodan strictly on-demand — *deps: 2.2* — **done when**: jobs fire on cron in a fast-forward integration test; `feed_health.last_status` updates on success and simulated failure.
- [ ] **2.4 [M]** Normalizer/dedupe pipeline: value normalization (lowercase, IP canonicalization, URL decode), upsert into `iocs` on `UNIQUE(type,value_norm)`, sightings insert with `ON CONFLICT DO NOTHING` — *deps: 2.2* — **done when**: replaying the same fixture twice yields identical row counts (dedupe >95%); normalization table has one runnable self-check per type.
- [ ] **2.5 [M]** Scoring engine: formula from BACKEND_SCHEMA.md, severity tiers, inline triggers T1/T2/T6 + nightly T3/T4 sweep job + rescore queue — *deps: 2.4* — **done when**: golden-vector test asserts exact score/severity for a 3-source IOC; T3 sweep recomputes only stale-by->24h rows.
- [ ] **2.6 [M]** Quota dashboard counters: `quota_usage` daily rollup written at job end; settings API exposes calls_made/calls_limit per feed — *deps: 2.1, 2.3* — **done when**: settings page shows live usage that increments after each ingest run; `quota_violations > 0` triggers a loud log warning.
- [ ] **2.7 [S]** Cache-before-call policy enforcement: lint-style test asserting every adapter method begins with cache lookup — *deps: 2.2* — **done when**: CI test fails if any adapter gains a direct HTTP call bypassing Redis.
- [ ] **2.8 [S]** Graceful degradation wiring: missing-key sources report health=`disabled`, UI hint surfaces — *deps: 2.3* — **done when**: booting with only OTX key set yields 1 active feed, 3 disabled, zero errors, other features unaffected.
- [ ] **2.9 [S]** Overnight soak runbook: docker compose up against live free tiers, capture metrics — *deps: 2.8* — **done when**: ≥5K unique IOCs ingested overnight, zero sustained 429s in logs, scores populated.

- **Done when**: overnight run yields ≥5K unique IOCs, zero sustained 429s, scores populated.

### Phase 3 — Dashboard & IOC UX (Week 3)

**Orchestration:** `api-agent` (skills: dignified-python) for summary/lookup endpoints; `ui-agent` (skills: ui-ux-pro-max, vercel-react-best-practices, web-design-guidelines) for screens; parallelizable once 2.5 lands.

Tasks:
- [ ] **3.1 [M]** Dashboard summary API (KPIs, trend, map aggregates) backed by `tih:dash:summary` cache — *deps: 2.5* — **done when**: second request within 60s served from Redis (verified via query counter); payload matches documented example shape.
- [ ] **3.2 [L]** Dashboard screen: KPI tiles, Tremor trend chart, react-simple-maps choropleth, polling refresh — *deps: 3.1, 1.7* — **done when**: renders with empty DB (empty states) and with soaked data; CVSS-convention severity colors per RESEARCH_NOTES §UI references.
- [ ] **3.3 [L]** IOC list: dense table, type/severity filters, text search, cursor pagination using `(severity, threat_score DESC, last_seen DESC)` index — *deps: 2.4* — **done when**: 100K-row synthetic dataset pages smoothly; EXPLAIN shows composite index used, no seq scans.
- [ ] **3.4 [M]** ⌘K command palette → `POST /api/iocs/lookup` flow (find-or-enrich, 202-poll pattern) — *deps: 3.3, 2.2* — **done when**: cached lookup <200ms; cold lookup shows pending state then resolves; PRD metric "≤2 clicks" demonstrated manually.
- [ ] **3.5 [L]** IOC detail page: score breakdown viz (per-source bars + bonus terms), sightings timeline, per-feed enrichment tabs — *deps: 3.1, 2.5* — **done when**: breakdown numbers match DB-stored components exactly; tabs show "disabled" state for unkeyed sources instead of erroring.
- [ ] **3.6 [S]** Export hooks on list/detail: CSV/JSON download (STIX export lands in Phase 4) — *deps: 3.3* — **done when**: downloads work and are audit-logged.

- **Done when**: full triage loop from APP_FLOW.md §1 and §2 works end-to-end.

### Phase 4 — Reports & YARA (Week 4)

**Orchestration:** `reports-agent` (skills: dignified-python, docx/pptx patterns not needed — WeasyPrint direct); `yara-agent` (skills: security-best-practices for FP discipline). WeasyPrint Docker deps validated day 1 per risk note.

Tasks:
- [ ] **4.0 [S]** WeasyPrint container smoke test (pango/cairo present) — *deps: 1.1* — **done when**: hello-world PDF generates inside the worker container. *(Day 1 gate per Risks.)*
- [ ] **4.1 [L]** Report generator: Jinja2 template → PDF via WeasyPrint; `report_artifacts` rows per format; daily scheduled digest (`REPORT_DAILY_CRON`) + on-demand; status lifecycle pending→generating→ready|failed — *deps: 2.5* — **done when**: digest generates <30s end-to-end on soaked data; failure marks status=failed with reason, doesn't crash worker.
- [ ] **4.2 [M]** Exports: CSV/JSON/STIX-JSON artifacts alongside PDF; file-streaming endpoint with audit logging — *deps: 4.1* — **done when**: all four formats downloadable, valid, and each download appends an `audit_log` row.
- [ ] **4.3 [L]** YARA Studio backend: string extraction from sample, rarity-ranked candidate rule generation, yara-python compile+match loop, benign-corpus validation gate, save/export — *deps: 1.7* — **done when**: generated rule compiles; validation refuses rules matching any benign corpus sample (`corpus_fp_free=false` blocks acceptance); `.yar` export downloads.
- [ ] **4.4 [M]** Frontend: Reports screen (list, generate button, artifact downloads) + YARA editor screen with live validation status — *deps: 4.2, 4.3* — **done when**: analyst completes upload→generate→validate→export without touching terminal.
- [ ] **4.5 [S]** Audit logging completeness pass over all mutating/export endpoints — *deps: 4.2* — **done when**: scripted crawl of every POST/PUT/download produces expected audit rows.

- **Done when**: PDF digest generates <30s; a generated rule compiles and passes benign-corpus check.

### Phase 5 — Post-MVP hardening + open-source release prep

#### 5a. Hardening
- [ ] **5.1 [S]** Empty states / first-run checklist; error toasts for quota exhaustion — **done when**: fresh install walks user through key setup; exhausted quota shows actionable toast naming the env var.
- [ ] **5.2 [M]** Accessibility pass (AA contrast, keyboard nav, reduced motion) — **done when**: axe-core scan clean on the six core screens; full keyboard-only triage loop possible.
- [ ] **5.3 [M]** Watchlists + email alerts `[post-MVP]`
- [ ] **5.4 [M]** MapLibre upgrade if choropleth insufficient `[post-MVP]`
- [ ] **5.5 [L]** Load pass at 50K IOCs/day; sightings partitioning decision `[post-MVP]`

#### 5b. Open-source release prep `[MVP]`

> User directive: project ships as OSS, AGPL-3.0 recommended. Nothing below is optional for the public repo.

- [ ] **5.6 [S]** LICENSE file: AGPL-3.0 full text at repo root + SPDX identifier line in README and pyproject/package.json headers — **done when**: GitHub recognizes license; `licensecheck` finds identifiers in all source files.
- [ ] **5.7 [M]** README: what/why (vs MISP/OpenCTI per RESEARCH_NOTES gap analysis), quickstart (`cp .env.example .env && docker compose up`), screenshots, **VT non-commercial restriction stated prominently**, per-feed quota table with links to provider terms, AGPL notice — **done when**: a stranger goes clone→running in <15 min following only the README; non-commercial caveat visible above the fold.
- [ ] **5.8 [S]** SECURITY.md: supported versions, private vulnerability reporting contact, disclosure policy — **done when**: file exists, linked from README, reporting address monitored.
- [ ] **5.9 [S]** docker-compose polish: healthchecks for pg/redis/api/web, named volumes for `DATA_DIR` persistence, restart policies, commented prod-vs-dev profile notes — **done when**: `docker compose down -v && up` fully recovers state; unhealthy service visibly fails healthcheck within 30s.
- [ ] **5.10 [S]** Secrets hygiene sweep: verify `.gitignore` blocks `.env`, `PROJECT_LOG.md`, `DATA_DIR/`; grep history for leaked secrets before making repo public; rotate anything ever committed — **done when**: `git log -p | grep -iE 'password|api_key|secret'` over full history returns nothing real; pre-commit hook (or CI check) rejects `.env` staging.
- [ ] **5.11 [S]** CONTRIBUTING.md + issue templates (bug/feature) + CI badge — **done when**: CI runs lint+tests on PR; templates render on new-issue page.
- [ ] **5.12 [S]** Tag v0.1.0, publish repo public, announce with license/quota caveats intact — **done when**: release exists; README quickstart validated from a clean machine clone.

## Dependency graph

```
Phase1 ──► Phase2 ──► Phase3 ──► Phase4 ──► Phase5a ──► Phase5b(release)
              │           ▲            ▲
              └── 2.9 soak┘            └── (4.0 gates 4.1; runs Week 4 Day 1)
Within Phase 3, list+detail (3.3–3.5) can start once schema exists (parallel to Phase 2 finish).
Phase 5b requires ALL prior phases complete — do not ship public before 5.10 passes.
```

## Risks to schedule
- WeasyPrint Docker deps (pango/cairo): validate in Week 4 day 1 (Task 4.0).
- VT non-commercial wording: document in README (Task 5.7) before any distribution.
- Free-tier quotas under multi-user OSS adoption: users sharing demo instances could burn their own quotas; mitigation is the per-instance limiter + quota dashboard (2.1, 2.6) — document "one instance = your own keys = your own quota" in README.
- Upstream API changes: adapters isolated (2.2); fixture-based tests make breakage visible in CI without spending live quota.
