# ThreatIntelHub — Research Notes
_Collected 2026-08-23 via web research. All later docs cite this file._

## Competitive landscape
| Product | Type | Positioning | Key takeaway |
|---|---|---|---|
| OpenCTI | OSS core / paid cloud | STIX 2.1 knowledge graph, 300+ connectors | Best OSS UI, but heavy ops (RabbitMQ+Redis+MinIO+ES, ~16GB RAM). https://opencti.filigran.io |
| MISP | OSS | Event/attribute model, auto IOC correlation, TAXII server | Powerful but complex UX, flat model, no report workflow. https://www.misp-project.org |
| Recorded Future | Commercial | ML risk-scored intel cloud; has Auto-YARA | Six-figure pricing; closed data. https://www.recordedfuture.com |
| Anomali ThreatStream | Commercial TIP | Feed aggregation + ML scoring for enterprise | $100Ks/yr, overkill for SMB. https://www.anomali.com/products/threatstream |
| AlienVault OTX | Free community | Pulses of community IOCs | Noisy data, weak scoring/correlation. https://otx.alienvault.com |
| GreyNoise | Freemium | Scanner noise filtering | Complement, not platform. https://viz.greynoise.io |

## Gap we exploit (solo analysts / SMB)
1. **Light deployment** — competitors need multi-service stacks; we ship one container.
2. **Finished intelligence** — MISP/OpenCTI emit raw events; we auto-generate daily/exec reports.
3. **Opinionated transparent scoring** — no hand-tuning taxonomies.
4. **Free-tier quota orchestration** — smart caching/batching/prioritization across VT/AbuseIPDB/Shodan limits.
5. **Integrated YARA generator** — neither OSS TIP ships one.

## API facts (verified)
- **OTX v1**: `https://otx.alienvault.com/api/v1`, header `X-OTX-API-KEY`. `/pulses/subscribed`, `/indicators/{type}/{value}/general` (+geo, passive_dns, malware, reputation sections). SDK `OTXv2`. Docs: https://otx.alienvault.com/api
- **VirusTotal v3**: `https://www.virustotal.com/api/v3`, header `x-apikey`. **Free tier: 4 req/min, 500 req/day, non-commercial.** `/files/{sha256}`, `/domains/{d}`, `/ip_addresses/{ip}`. Docs: https://docs.virustotal.com/reference/overview
- **AbuseIPDB v2**: `https://api.abuseipdb.com/api/v2`, header `Key:`. Free: **check 1000/day, blacklist 5/day (10K rows)**. `abuseConfidenceScore` 0–100. 429 + `X-RateLimit-*` headers. Docs: https://docs.abuseipdb.com/
- **Shodan**: `https://api.shodan.io`, `key` param. `/shodan/host/{ip}` costs no credits; `/shodan/host/search` = 1 credit/page. ~1 req/s. Free bonus APIs: InternetDB (`https://internetdb.shodan.io`), CVEDB (`https://cvedb.shodan.io`). Docs: https://developer.shodan.io/api

## Scoring & correlation conventions
- STIX 2.1 native 0–100 `confidence`; TAXII 2.1 transport is table stakes for interop. https://oasis-open.github.io/cti-documentation/
- Standard confidence formula: weighted **source reliability × age decay × sightings × cross-source agreement × enrichment signals**. Multi-feed presence sharply raises severity. https://www.cyware.com/resources/security-guides/what-is-confidence-scoring-in-threat-intelligence
- Admiralty-style A1–F6 source grading common (MISP). Academic ref: https://www.sciencedirect.com/science/article/pii/S0167404824002773
- Practical flow: normalize → dedupe → merge sources → exponential age decay → weighted sum → threshold tiers (auto-block / investigate / monitor).

## UI references (see UI_UX_DESIGN_BRIEF.md)
Severity colors follow CVSS convention (Critical=red, High=orange, Medium=amber, Low=green/blue, None=gray) — keep mapping uniform across score bars and badges (ref: https://github.com/elastic/kibana/issues/156322).
Layout patterns copied from GreyNoise Visualizer (left search rail + right detail panel), Shodan Maps (dark choropleth + click-through drilldown), OpenCTI demo (entity graph + timeline tabs): https://viz.greynoise.io · https://maps.shodan.io · https://demo.opencti.io
