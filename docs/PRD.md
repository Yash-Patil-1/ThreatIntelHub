# PRD — ThreatIntelHub

## Problem
Solo analysts and small security teams can't afford enterprise TIPs ($100Ks/yr, see RESEARCH_NOTES.md) and find MISP/OpenCTI too operationally heavy (OpenCTI alone wants ~16GB RAM across RabbitMQ+Redis+MinIO+ES). They need: aggregated OSINT feeds → deduplicated/correlated IOCs → transparent threat scores → ready-to-share reports — in one lightweight tool they can run on a laptop or a $10 VPS, using only free/cheap API tiers.

**The wedge**: an open-source TIP that deploys in minutes on free-tier APIs and outputs *finished intelligence* (reports, YARA rules), not raw event streams. MISP/OpenCTI compete on breadth; we compete on time-to-value for one person who needs answers today.

## Target users & personas

1. **Sam, solo SOC analyst (SMB)** — watches feeds daily, needs a triage queue ranked by score, exports IOCs to firewall/SIEM.
   - *Day in the life*: 8:30am coffee, opens ThreatIntelHub dashboard before the ticket queue. Overnight digest shows 3 new IOCs scored ≥85 (critical) — two IPs from OTX pulses that also appear on the AbuseIPDB blacklist, so correlation already bumped them up. Sam eyeballs the enrichment tabs (Shodan open ports, VT verdicts), decides to auto-block the top IP via CSV export → firewall import, marks one "monitor", dismisses one false positive (a CDN edge node). Total: 12 minutes. Without the tool this was an hour of tab-hopping across four vendor consoles.
   - *Success for Sam*: zero quota anxiety (tool manages free-tier limits), export formats his SIEM accepts without massaging.
2. **Dana, incident responder** — pastes an IP/hash/domain during an incident, needs one-click enrichment from all four feeds + history.
   - *Day in the life*: Page at 2pm — workstation beaconing to `185.x.x.x`. Dana pastes the IP into the ⌘K lookup: cache-warm result in <200ms showing Shodan banner history ("Cobalt Strike team server, last seen 6 days ago"), AbuseIPDB confidence 92, three OTX pulses containing it. She screenshots the IOC detail page into her incident notes, then exports the correlated sibling IOCs as STIX-JSON to hand the client's SOC. Total: under 5 minutes from page to shared intel.
   - *Success for Dana*: one input field, all sources, historical context she didn't have to pay for.
3. **Alex, malware researcher** — extracts strings from a sample, generates + validates YARA rules without running yarGen separately.
   - *Day in the life*: Drops a new sample's SHA256 into the tool; VT file report pulls (on-demand, respects the 4/min limit via queueing). Extracts candidate strings in-app, clicks Generate Rule; the validator runs it against a benign corpus and flags two over-broad strings. Alex tightens them, re-validates green, exports the `.yar` file. The rule goes in the family's tracking repo same afternoon.
   - *Success for Alex*: no local yarGen/yara-python setup, no false-positive rules shipped.

## Goals
- G1: Aggregate OTX, VirusTotal, AbuseIPDB, Shodan on a schedule **and** on demand, using only free-tier quotas (users supply their own keys via `.env`; see TRD §Free-tier quota strategy).
- G2: Correlate IOCs across feeds; multi-feed presence raises severity automatically.
- G3: Transparent 0–100 threat score (formula visible in UI, thresholds ≥85 critical / ≥65 high / ≥40 medium / ≥15 low).
- G4: Auto-generated daily digest + on-demand executive report (PDF/JSON/CSV export).
- G5: YARA rule generator from sample strings/hashes, validated with yara-python against a benign corpus.
- G6: Run entirely on free/zero-key data sources where possible; degrade gracefully when any API key is absent or exhausted.

## Non-goals (v1)
Real-time streaming feeds (paid plans), SIEM bidirectional sync, STIX/TAXII server mode (import/export of STIX JSON only), multi-tenant teams/RBAC, ML scoring, paid-API integrations, commercial-use guarantees for VT-sourced data (VT free tier is non-commercial — documented constraint, not a bug).

## Prioritized features (MoSCoW)

| Must | Should | Could | Won't (v1) |
|---|---|---|---|
| Feed ingestion (4 sources) w/ scheduler + quota manager | IOC detail page w/ per-feed raw data tabs | World-map choropleth by source country | TAXII server |
| IOC store w/ normalization + dedupe | Search/filter dashboard (⌘K lookup) | Watchlists + alert rules (email) | Multi-user RBAC |
| Cross-feed correlation + scoring engine | CSV/JSON/STIX-JSON export | Dark-web keyword monitor | Streaming API |
| Daily digest + report generation (PDF/MD) | YARA generator w/ validation loop | Public shareable IOC pages | Mobile app |
| Auth (single admin user), API keys config UI | Enrichment pipeline plugins | Browser extension | |

### Acceptance criteria

**M1 — Feed ingestion (OTX, VT, AbuseIPDB blacklist, Shodan host lookup)**
- Each adapter implements one interface (`fetch_since(cursor)`); a failing feed never blocks or corrupts others' ingestion runs.
- Scheduled pulls respect per-feed budgets (see TRD): OTX hourly, AbuseIPDB blacklist daily (≤5 calls/day free tier), VT/Shodan on-demand only in v1.
- Zero sustained HTTP 429 responses over a 7-day soak run; every pull updates a persisted cursor so restart resumes, never re-pulls from scratch.
- Missing API key = feed silently skipped with visible "not configured" state in UI — never a crash, never a partial ingest.

**M2 — IOC store**
- Normalization canonicalizes: IPs to int form, domains lowercased/punycode-decoded, hashes case-folded and length-detected (md5/sha1/sha256). Dedupe key `(type, normalized_value)` unique-constrained at DB level.
- Re-ingesting the identical feed yields >95% dedupe rate (existing rows updated, not duplicated).
- Raw per-feed payloads retained in JSONB so nothing is lost to normalization bugs.

**M3 — Correlation + scoring**
- Sightings grouped by dedupe key across sources within a configurable window (default 72h); `correlation_count` and `source_set` stored denormalized.
- Score recomputed only on new sighting/enrichment events (never per request); formula and current weights displayed on every IOC page.
- Multi-source presence applies cross-source agreement bonus such that an IOC on 3+ feeds cannot score below the "high" threshold if any source rates it maliciously.

**M4 — Reports**
- Daily digest auto-generates at configured hour; contains new/critical IOCs, score deltas, per-feed stats.
- Executive PDF renders end-to-end <30s including WeasyPrint conversion; JSON/CSV/STIX-JSON exports available for any filtered view.
- Exports are audit-logged (who/when/what filter).

**M5 — Auth + key management**
- Single admin login (session cookie, argon2id hash); failed-attempt lockout after 5 tries/15min.
- API keys entered in UI are Fernet-encrypted at rest, masked in UI, never logged, testable via a "verify" button that pings each endpoint cheaply.

**S1..S5 (Should)** ship with basic happy-path coverage; each may drop to v1.1 without blocking MVP if schedule slips — decision recorded in IMPLEMENTATION_PLAN.md.

## Open Source Strategy
The project ships as open source from commit one. This is positioning as much as ethics: the lightweight-wedge story ("inspect it, fork it, self-host it") only works if the code is actually inspectable.

### License options (open decision)
| Option | Copyleft | Closed forks? | Network-use clause | Fit for a TIP |
|---|---|---|---|---|
| **AGPL-3.0** ✅ recommended | Strong | No — forks must stay open | Yes — SaaS hosting triggers source disclosure | Best fit: prevents a company from wrapping ThreatIntelHub in a closed commercial TIP |
| GPL-3.0 | Strong | No | No (only distribution triggers) | Weaker here: someone could host a closed SaaS version |
| MIT / Apache-2.0 | None | Yes | No | Permissive alternative if we want maximum adoption/forks; Apache-2.0 adds patent grant |

**Recommendation**: AGPL-3.0. A threat-intel platform is exactly the category competitors would love to close-source-fork; AGPL keeps derivative SaaS honest while leaving internal/self-hosted use completely free. Trade-off accepted: some corporate contributors avoid AGPL codebases. **Decision needed from user before Phase 1** (tracked in PROJECT_LOG.md open questions). MIT/Apache-2.0 remains acceptable if user prioritizes contributor friction over fork protection.

### Community contribution model
- **Core vs plugin split** (drives what accepts external PRs):
  - *Core* (maintained by us, high review bar): scheduler/quota manager, normalizer, correlator, scoring engine, auth, DB schema. Changes here need tests + a design note.
  - *Plugins* (community-friendly, low review bar): feed adapters beyond the initial four, enrichment providers, report templates, YARA string-rank heuristics. Plugin interface documented in TRD §Key components #8.
- Contribution path: GitHub issues → feature proposal template for anything touching core → PRs require passing CI (lint + tests) → maintainer merge. First milestone: good-first-issue labels + adapter-authoring guide, since feed adapters are the natural community entry point.
- Governance stays BDFL-style until >5 regular contributors; revisit then.

## Success metrics
Measurable targets, checked monthly post-launch:

| Metric | Target | How measured |
|---|---|---|
| Ingestion throughput | ≥10K unique IOCs/day across 4 feeds | Ingest job counters |
| Quota discipline | 0 sustained HTTP 429s over any rolling 24h | Rate-limit middleware logs |
| Dedupe correctness | >95% dedupe rate on re-ingest | Normalizer unit benchmark vs fixture feed |
| Enrichment latency | Cold <5s, warm <200ms (p95) | API timing middleware |
| Report generation | <30s end-to-end (p95) | Report job timer |
| Time-to-answer (Dana flow) | Paste IOC → full enrichment ≤2 clicks, <5s cold | Manual UX test each release |
| Deployment footprint | Full stack <2GB RAM on commodity VPS | Docker stats during soak |
| Setup time | Clone → running stack ≤15 min on clean Docker host | Timed install runbook each release |
| Community health (post-launch) | ≥10 external issues/month by month 3; ≥1 merged external PR by month 6 | GitHub metrics |

## Competitor positioning
See RESEARCH_NOTES.md table. Positioning statement:

> ThreatIntelHub is the open-source TIP you run on a laptop: one Docker Compose stack under 2GB RAM (vs OpenCTI's ~16GB multi-service deployment), finished-intelligence output instead of raw event firehoses (vs MISP), and transparent scoring you can read in one screen — all on free-tier APIs, versus six-figure enterprise pricing (Recorded Future, Anomali ThreatStream).

We do not compete on connector count (OpenCTI: 300+) or taxonomy depth. We win on **time-to-first-insight** (<15 min install → first digest) and **total cost of ownership** ($0 software, $0 API spend within free tiers).

## Risks
1. **VT free tier (500 req/day, non-commercial)** — *Mitigation*: aggressive caching (24h TTL default), on-demand-only lookups prioritized by user action, prominent non-commercial notice in docs and UI when VT key configured, graceful degradation to other feeds when exhausted. Users doing commercial work are pointed to VT Premium in the docs.
2. **OTX noise/unvetted pulses** — *Mitigation*: source-reliability weighting in scoring, confidence floor before display, per-source mute toggle so users can demote OTX-only findings.
3. **YARA false positives** — *Mitigation*: mandatory benign-corpus validation step before a rule is marked accepted; unvalidated rules visibly flagged in UI/export.
4. **API changes upstream** — *Mitigation*: adapter pattern isolates each feed client; contract tests pin response schemas per adapter; adapters are the plugin surface so community can patch fast between releases.
5. **License choice blocks contributions** — *Risk of AGPL*: some corporate devs can't contribute. *Mitigation*: document dual stance clearly; if adoption stalls by month 6 with evidence AGPL is the cause, revisit (relicensing requires all-contributor consent — decide deliberately, not retroactively).
6. **Scope creep toward OpenCTI** — every "add RBAC/multi-user" request tempts us into heavyweight territory. *Mitigation*: non-goals list above is contractual for v1; plugin architecture absorbs extensions without core growth.

## Open decisions (blocking Phase 1)
1. License: AGPL-3.0 (recommended) vs MIT/Apache-2.0 — see Open Source Strategy above.
2. Deployment target: local Docker only, or VPS/cloud profile also supported day one (affects compose defaults).
