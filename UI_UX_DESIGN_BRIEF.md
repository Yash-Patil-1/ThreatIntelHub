# UI/UX Design Brief — ThreatIntelHub

## Design direction
Dark SOC console, **restrained cyber**: near-black navy surfaces with one neon accent; severity colors are the only other saturated hues. Elevation via surface layering and subtle `white/10%` borders — no heavy shadows. Grid/dot background texture on hero surfaces only. (Pattern refs: RESEARCH_NOTES.md §UI.)

## Moodboard / inspiration links
- https://dribbble.com/shots/27463648-Cybersecurity-Operations-Command-Center-Dashboard
- https://dribbble.com/shots/27622883-Cyber-Defense-Dashboard-Design (SentinelX globe)
- https://dribbble.com/shots/26652336-Cybersecurity-Dashboard-CyFocus (orange/red heatmaps)
- https://www.behance.net/gallery/229356007/Repid7-Cybersecurity-Dashboard
- Free Figma SOC console: https://www.figma.com/community/file/1608389822266370987/security-operations-dashboard
- Product-layout references to copy: GreyNoise Visualizer (https://viz.greynoise.io), Shodan Maps (https://maps.shodan.io), OpenCTI demo (https://demo.opencti.io)

## Color & type system
- Background: `#0a0e17` (slate-950-ish); surfaces: `#111827`; raised surfaces: `#1f2937`; text: slate-200; muted: slate-400.
- Primary accent: **cyan `#22d3ee`** (interactive elements, focus rings, active nav).
- Severity (CVSS convention, uniform across badges/bars/map) — see Severity Color Contract below.
- Fonts: **Inter** (UI) + **JetBrains Mono** (IPs, hashes, CVE IDs, YARA code). Tabular numerals (`tabular-nums`) in all tables so columns don't jitter during live feed updates.

### Severity Color Contract
| Level | Hex | On-dark contrast vs `#0a0e17` | Allowed usages | Forbidden usages |
|---|---|---|---|---|
| Critical | `#ef4444` red | 5.1:1 ✅ | severity pills/badges, score bars ≥ threshold, choropleth fill, critical-only glow border, "block" tier label | links, buttons, focus rings, decorative accents |
| High | `#f97316` orange | 7.3:1 ✅ | same set as critical | interactive states |
| Medium | `#eab308` amber | 10.4:1 ✅ | same set as critical | success/positive messaging |
| Low | `#22c55e` green | 8.9:1 ✅ | same set as critical | "online/healthy" status dots — status uses cyan or slate instead |
| Info/None | `#94a3b8` slate-400 | 7.0:1 ✅ | neutral badges, empty score bar track | — |

Contract rules: severity colors are **reserved strictly for severity data**. Any non-severity UI (buttons, charts of non-threat data, quota meters, links) uses cyan or slate only, so a red element anywhere always means "critical threat." For text smaller than 18px on tinted badge backgrounds (`red-500/15%` etc.), use the lightened variants `#fca5a5` / `#fdba74` / `#fde047` / `#86efac` for the glyph to keep ≥4.5:1 on the tinted surface.

## Component sources (buildable)
| Need | Source |
|---|---|
| Tables, cards, badges, tabs, dialog, select, command palette | shadcn/ui — https://ui.shadcn.com |
| Charts (trend area/bar/donut, KPI cards, sparklines, BarList, progress meters) | Tremor — https://www.tremor.so · blocks: https://blocks.tremor.so |
| World choropleth map | react-simple-maps + world-atlas topojson — https://www.react-simple-maps.io/examples/world-choropleth-mapchart/ ; fallback MapLibre https://maplibre.org |
| Live IOC feed animation | Magic UI Animated List — https://magicui.design |
| Cyber effects (dot pattern grid, glow border on critical only) | Aceternity — https://ui.aceternity.com/components |

### Component inventory → screens
| Region | Component(s) |
|---|---|
| Sidebar nav | shadcn `Tooltip` (icon rail) + custom active-state ring (cyan) |
| ⌘K palette | shadcn `CommandDialog`, mono font results, keyboard-first |
| KPI row | Tremor `CategoryBar`/KPI card block ×3–4, sparkline inset |
| Trend chart | Tremor `AreaChart` (cyan line, severity-tinted stacked bands optional) |
| World map | react-simple-maps `ComposableMap` + `Geographies`; tooltip via shadcn `HoverCard` |
| Live feed rail | Magic UI `AnimatedList` of compact IOC cards |
| IOC table | shadcn `Table` inside virtualized wrapper (TanStack Virtual); sticky `TableHeader`; severity = `Badge` variant per contract |
| Score bar | custom div over Tremor `ProgressBar` track; mono numeral label |
| Feed-source dots | shadcn `Tooltip`-wrapped 8px circles (one per contributing feed) |
| Detail tabs | shadcn `Tabs` (OTX / VT / AbuseIPDB / Shodan) |
| Copy actions | shadcn `Button` ghost + sonner toast confirmation |
| Quota meters | Tremor `ProgressBar` + `Badge` ("347/500") in sidebar footer + Settings |
| Enrichment pending | `Badge` outline + pulsing dot (shadcn `Skeleton` for unknown fields) |
| Reports preview | shadcn `ScrollArea` + `Separator`; export via `DropdownMenu` |
| YARA editor | CodeMirror/Monaco-lite in JetBrains Mono, shadcn `Card` shell |
| Setup wizard | shadcn `Stepper` pattern (custom on `Card` steps), masked `Input` type=password |

## Key screens — region-by-region layout specs

Text wireframes use `[region]` blocks; desktop-first at ≥1280px unless noted.

### 1. Dashboard (home)
```
┌──────────────────────────────────────────────────────────────┐
│ [A Topbar] page title "Dashboard" · date-range Select · ⌘K hint │
├───┬──────────────────────────────────────────┬───────────────┤
│ S │ [B KPI row — 4 equal cards]              │ [E Live feed  │
│ i │  New IOCs 24h · Criticals · Feed health  │  rail ~320px  │
│ d │  · VT quota remaining                    │  full height] │
│ e ├──────────────────────────┬───────────────┤               │
│ b │ [C Threat trend AreaChart│ [D World      │               │
│ a │  ~60% width]             │  choropleth   │               │
│ r │                          │  ~40% width]  │               │
└───┴──────────────────────────┴───────────────┴───────────────┘
```
- **B KPI cards**: value in Inter semibold 28px tabular; delta vs yesterday as small muted line; click navigates to pre-filtered `/iocs`. VT quota card shows `ProgressBar` turning amber at ≤20% and red-badge "exhausted" at 0 — this is the one place a red *badge* is permitted outside severity (labeled explicitly "quota", never styled as a severity pill).
- **C trend chart**: 14-day default range, cyan area with `white/10%` grid lines; hover crosshair shows date + count in a Tremor tooltip.
- **D map**: countries shaded by source-IOC count using the severity ramp; hover = country name + count HoverCard; click drills to `/iocs?source_country=XX`.
- **E live rail**: newest-enriched IOCs streaming in top; each mini-card = severity pill, mono value, relative time; click → detail. Max ~50 items, older fall off.

States:
- *Empty (first run)*: B–D replaced by single setup-checklist Card ("Add API keys → run first pull → dashboard goes live"), each step linking into Settings/wizard.
- *Loading*: KPI skeletons (pulse), chart shimmer block, map renders base geography immediately then fades fills in.
- *Feed down*: live rail header dot turns slate + "paused" label; last-known items stay visible, grayed.
- *Quota exhausted*: KPI quota card shows red-outline badge "Daily limit reached — resets HH:MM UTC"; enrichment buttons elsewhere show disabled-with-tooltip.

### 2. IOC list
```
┌──────────────────────────────────────────────────────────────┐
│ [A Filter bar] severity MultiSelect · type Select · source    │
│    Select · saved-filter chips · search Input                 │
├──────────────────────────────────────────────────────────────┤
│ [B Table — sticky header, ~32px rows, virtualized]            │
│ sev-pill │ value(mono) │ type │ sources(dots) │ score-bar │   │
│          │             │       │              │ last-seen(rel)│
├──────────────────────────────────────────────────────────────┤
│ [C Footer] row count · pagination · export DropdownMenu       │
└──────────────────────────────────────────────────────────────┘
```
- Row click opens detail; rows are focusable (`tabindex=0`, Enter opens) for keyboard nav.
- Sources-as-dots: OTX=cyan, VT=violet, AbuseIPDB=slate-light, Shodan=teal outlines — deliberately NOT severity colors.
- Saved filters render as dismissible chips above the table.

States: zero results → centered empty illustration + "Clear filters" button; loading → skeleton rows matching row height; partial enrichment (some feeds pending) → source dots show hollow placeholder with tooltip "enriching…"; error fetching → inline alert banner atop table with Retry.

### 3. IOC detail
```
┌──────────────────────────────────────────────────────────────┐
│ [A Header] value (mono, copy btn) · severity pill · score     │
│    numeral · stale/new badge · Re-enrich button               │
├───────────────────────────────┬──────────────────────────────┤
│ [B Left column ~55%]          │ [C Right column ~45%]        │
│  Score breakdown card         │  Tabs: OTX│VT│AbuseIPDB│Shodan│
│  (formula terms as labeled    │  per-feed raw JSON rendered  │
│   horizontal bars + weights)  │  as key/value list, mono     │
│  Sightings timeline           │                              │
│  Correlated IOCs BarList      │                              │
└───────────────────────────────┴──────────────────────────────┘
```
- Score breakdown makes the formula transparent: each term (source reliability, age decay, sightings, cross-source agreement, enrichment signals) as a labeled bar + weight; total in large tabular numeral colored by severity band.
- Every raw value has a copy affordance; timestamps show both relative and absolute on hover.

States: pending enrichment → breakdown card shows Skeleton bars + "Enrichment running…" Badge with pulsing dot and auto-refresh (see APP_FLOW async flow); feed failed → its tab shows inline error card with the feed name, HTTP reason, and Retry-this-feed; stale IOC → muted banner "Score decayed below display threshold on DATE".

### 4. Reports
```
[A Toolbar] Generate-now Button (primary cyan) · schedule status
[B Split view] left: report list (date, type badge, size)
              right: preview pane (rendered digest) + export menu
```
Generate-now becomes an in-place progress row (queued → running spinner → done) without navigating away. Failed jobs keep their row with a red-outline "failed" chip + Retry — again outline style, not a severity pill.

### 5. YARA Studio
```
[A Input panel] paste strings/hashes/textarea + linked-IOC picker
[B Rule editor] mono editor, line numbers, syntax highlight
[C Validate bar] compile result badge ✓/✗ · corpus FP scan result
                 (matches count) · Save / Export .yar buttons
```
Validation errors render inline under the offending editor line where possible.

### 6. Settings
Three stacked Cards: **API keys** (per-feed masked inputs, Test button per key showing inline ✓ latency or ✗ error, never blocking save of others), **Schedules** (pull interval selects + next-run times), **Quota usage** (per-feed Tremor ProgressBar with used/limit numerals, reset-time caption). First-run users are routed here (or into the setup wizard) automatically — see APP_FLOW §First-run setup.

## Responsive notes (desktop-first ≥1280px)
- **≥1280px**: full three-column layout (sidebar 64px icon rail + main + right panel/live rail 320px).
- **1024–1279px**: right contextual panels collapse into main column below content or into a slide-over Drawer; live feed becomes a toggleable drawer.
- **<1024px**: sidebar collapses to hamburger sheet; tables switch from full columns to a condensed card-row layout (severity pill + mono value + score bar; secondary cols move into expandable row detail). Dashboard KPI row wraps 4→2→1. Map keeps min-height 300px. This app is analyst-desktop-first; mobile is functional, not optimized.
- All breakpoints preserve keyboard order = visual order; no content hidden behind hover-only on touch.

## Accessibility (WCAG 2.1 AA)
- **Contrast**: all severity colors verified ≥4.5:1 against `#0a0e17` and against their own `/15%` tinted badge surfaces via lightened glyph variants (table above). Cyan `#22d3ee` on dark = 10.9:1. Muted text slate-400 = 7.0:1; never go below slate-500 for meaningful text.
- **Severity must not rely on color alone**: every pill/bar carries a text label ("CRITICAL", numeric score); map shading paired with hover/click numeric tooltips; score bars have aria-valuenow.
- **Keyboard**: complete tab path through nav → filters → table rows → detail tabs → copy buttons; ⌘K palette traps focus, Esc closes; roving tabindex in table; skip-to-content link first in DOM.
- **Focus**: global `focus-visible` ring = 2px cyan offset 2px; never removed.
- **Live regions**: live feed container `aria-live="polite"` announcing max 1 item per batch; enrichment-pending badges flip announced when resolved.
- **Motion**: `prefers-reduced-motion` disables AnimatedList slide-ins, pulse dots (static outline instead), chart entry animations, glow effects.
- **Screen-reader naming**: icon-only sidebar/nav buttons get `aria-label`; source dots grouped as "Sources: OTX, VirusTotal" via visually-hidden text.
