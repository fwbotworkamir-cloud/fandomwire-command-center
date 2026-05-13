# FandomWire — Bot Traffic Protection Plan (Action-Ordered)

**Companion to:** `docs/bot-traffic-forensic-analysis.md` (analysis & forensic queries)
**This document:** the concrete, sequenced execution plan — what to ship, in what order, with thresholds, rollback procedures, and success metrics.

**Posture:** Layered defense. **Every layer logs before it blocks.** No layer ships at "Block" action before 24h in "Log" mode and visual diff of CWV + Search Console.

---

## 0. Mission & Success Criteria

| Metric | Today (assumed) | Target (90 days) | Floor (do-not-cross) |
|---|---|---|---|
| Bot share of pageviews (CF BotScore ≤ 30) | unknown, suspected 30–60% | < 10% | — |
| GA4 engagement-time p50 (article pages) | ~0.98s | ≥ 12s | ≥ 8s |
| Engagement-histogram bot mode (750–1250ms) sessions | suspected dominant | < 5% of sessions | < 15% |
| Real-user ad-impression rate per session | unknown | +30% from baseline | not below baseline |
| Search Console clicks vs GA4 sessions ratio | unknown divergence | within ±15% per page | within ±25% |
| Google Discover impressions | flat/declining | trending up | not declining > 10% w/w |
| CWV p75 INP (after beacon ships) | baseline | within +5ms of baseline | within +20ms |
| Verified Googlebot crawl rate | baseline | not lower than baseline | within −10% |

Hard rules:
- No layer ships if it degrades **CWV p75 INP by >20ms** or **Googlebot crawl rate by >10%**
- Every rule has a documented rollback < 5 minutes (single dashboard toggle or single commit revert)
- No CAPTCHA on article pages without explicit Editorial sign-off

---

## 1. Defense-in-Depth Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  L0  DNS / Cloudflare                                            │
│        - Logpush → BigQuery (data layer; informs L1–L4)          │
│        - Bot Management ML  (BotScore field)                     │
├─────────────────────────────────────────────────────────────────┤
│  L1  Cloudflare WAF                                              │
│        - Verified-bot allowlist (Skip)                           │
│        - Static signature blocks (HeadlessChrome, etc.)          │
│        - sec-ch-ua consistency challenge                         │
│        - DC-ASN challenge                                        │
│        - Rate limits (per-IP, per-ASN, per-JA3)                  │
│        - Honeypot-path block                                     │
├─────────────────────────────────────────────────────────────────┤
│  L2  Edge middleware (Next.js / Cloudflare Worker)               │
│        - Mint HMAC trust token                                   │
│        - Apply cached trust-score (KV)                           │
│        - Cache article HTML for verified bots (crawl protect)    │
├─────────────────────────────────────────────────────────────────┤
│  L3  Client beacon + trust scoring                               │
│        - Fingerprint + interaction telemetry → /api/trust        │
│        - Honeypot anchor                                         │
│        - Ad render gated on interaction signal                   │
├─────────────────────────────────────────────────────────────────┤
│  L4  Server-side analytics & ad pipeline                         │
│        - GA4 Measurement Protocol with signed token              │
│        - Trust-score band filter before forward                  │
│        - Prebid/GPT trust-band gating                            │
├─────────────────────────────────────────────────────────────────┤
│  L5  Detection & response                                        │
│        - Anomaly alerting (engagement EMD, JA3 collapse, ASN)    │
│        - ML scoring v2 (Isolation Forest, HDBSCAN)               │
│        - Dashboard widgets in command-center                     │
└─────────────────────────────────────────────────────────────────┘
```

Each layer below depends on the layer above being healthy. **Build top-down.**

---

## 2. Phase 0 — Visibility (Days 1–3)

**Goal:** convert "0.92 confidence" to "0.99 confidence" with data.
**Blocks all later phases.** Cannot defend what you can't see.

### 2.1 Cloudflare Logpush → BigQuery
- Open Cloudflare dashboard → Analytics & Logs → Logpush
- Destination: GCP BigQuery (recommended) or R2 + scheduled load
- Dataset: `fandomwire_cloudflare.http_requests`
- Fields (required): `EdgeStartTimestamp, ClientIP, ClientASN, ClientCountry, ClientRequestUserAgent, ClientRequestPath, ClientRequestReferer, ClientRequestHost, ClientSSLProtocol, ClientSSLCipher, ClientTCPRTTMs, BotScore, BotScoreSrc, JA3Hash, JA4, EdgeResponseStatus, WAFAttackScore, RequestHeaders, ResponseHeaders`
- Sampling: 100% for 30 days, then 10% sampling for archival
- Cost ceiling: ~$0.05/GB; budget $200/mo

**Verification:** within 1 hour, `SELECT COUNT(*) FROM http_requests WHERE EdgeStartTimestamp > NOW() - INTERVAL 10 MINUTE` returns expected volume.

### 2.2 GA4 → BigQuery export
- GA4 Admin → BigQuery Linking → Add → Daily export (Streaming optional, $25/mo extra; recommend yes for real-time anomaly)
- Project: same as Cloudflare for cheap joins
- Dataset: `fandomwire_ga4.analytics_<property_id>`

**Verification:** `events_*` table starts populating within 24h. Streaming `events_intraday_*` within 1h.

### 2.3 Search Console export
- GSC → Settings → Bulk Data Export → BigQuery
- Dataset: `fandomwire_gsc`
- Provides ground truth for "real" referred traffic

**Verification:** 24–48h for first daily batch.

### 2.4 Run the diagnostic queries (analysis doc §6)
Run all five queries (engagement histogram, interaction-free ratio, ASN clustering, JA3 collapse, UA consistency) and fill the §7 anomaly report template. **Decision gate:** the histogram-shape result determines whether Phase 1 ships aggressively or conservatively.

### 2.5 Phase 0 Deliverables
- [ ] BQ tables receiving Cloudflare data
- [ ] BQ tables receiving GA4 data
- [ ] BQ tables receiving Search Console data
- [ ] Anomaly report filled (`docs/anomaly-report-<date>.md`)
- [ ] Top 10 suspicious ASNs identified
- [ ] Top 5 collapsed JA3 fingerprints identified
- [ ] Confirmed engagement-histogram shape

**Owner:** Data eng (lead) + Security
**Effort:** 1.5 days
**Cost:** ~$250/mo recurring

---

## 3. Phase 1 — Edge Filtering (Days 4–10)

**Goal:** stop the cheapest, highest-confidence bots at Cloudflare. Save Next.js compute.

### 3.1 Cloudflare Bot Management
- Plan: Pro min for Bot Fight Mode; Business+ for Super Bot Fight Mode (recommended); Enterprise for Bot Management ML + `BotScore` field as a rule input
- Action: enable Bot Management
- **Critical:** also enable "Verified Bots" allowlist (Googlebot, Bingbot, Applebot, DuckDuckBot, etc.) — Cloudflare validates by reverse DNS

### 3.2 WAF Rule Deployment Sequence

Each rule ships in **5 stages**, never skip:

```
Stage 1 (Day N+0): action = Log
Stage 2 (Day N+1): review 24h logs; tune predicate; remain Log
Stage 3 (Day N+2): action = Managed Challenge (most permissive challenge)
Stage 4 (Day N+4): review 48h; if false-positive rate < 0.5% of human sessions
                   → action = JS Challenge (or stay at Managed Challenge if SEO-sensitive)
Stage 5 (Day N+7): only if precision proven, escalate to Block; keep Log copy for audit
```

#### Rule 1 — Verified-bot allowlist (Skip; deploy first, always)
```
(cf.client.bot)
or (http.user_agent matches "Googlebot|Bingbot|Applebot|DuckDuckBot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|TelegramBot|WhatsApp")
```
Action: **Skip** (must evaluate before all challenge rules in rule order).

#### Rule 2 — Static signature blocks
```
http.user_agent contains "HeadlessChrome"
or http.user_agent contains "Puppeteer"
or http.user_agent contains "Playwright"
or http.user_agent contains "phantomjs"
or http.user_agent contains "Selenium"
or http.user_agent contains "Electron/"
or http.user_agent eq ""
```
Action: **Block** (low FP risk; safe to skip the Log → Challenge stages and go straight to Block after 24h Log).

#### Rule 3 — sec-ch-ua consistency
```
http.user_agent contains "Chrome/"
and any(http.request.uri.path[*] matches "^/(?!api/|_next/|sitemap|robots)")
and not any(http.request.headers.names[*] eq "sec-ch-ua")
and not cf.client.bot
```
Action: **Managed Challenge** (high precision; small FP risk for very old Chrome).

#### Rule 4 — DC ASN challenge
```
ip.geoip.asnum in {
  14061  16509  14618  16276  24940  20473  63949  9009
  51852  60068  202425  208046  399629  202196  203817
}
and not cf.client.bot
and http.request.uri.path matches "^/(?!api/|_next/|sitemap|robots|feed)"
```
Action: **Managed Challenge**.
**Note:** AS15169 (Google Cloud) intentionally excluded — Googlebot already covered by Rule 1, and many legit users tunnel through GCP-hosted VPNs.

#### Rule 5 — Honeypot path block + tagging
```
http.request.uri.path eq "/bot-trap" or http.request.uri.path matches "^/bot-trap/"
```
Action: **Block** + Workers KV write to ban list (TTL 24h).

#### Rule 6 — JA3 collapse (deploy only after Phase 0 identifies top JA3s)
```
cf.bot_management.ja3_hash in { "<top 5 collapsed JA3s from §2.4>" }
and not cf.client.bot
```
Action: **JS Challenge**.

#### Rule 7 — Rate limits (separate Rate Limiting Rules section, not WAF)
- **Per-IP:** 100 req/min on `/article/*` → Managed Challenge for 5 min
- **Per-ASN (excluding Verified Bots):** 5000 req/min → Managed Challenge for 5 min
- **Per-JA3:** 10000 req/min → Block for 1 hour
- **`/api/trust`:** 60 req/min/IP → 429 (prevents beacon flooding)

### 3.3 Phase 1 Rollback
- All rules toggleable from Cloudflare dashboard
- Rule order documented in `infra/cloudflare-rules.md` (commit alongside dashboard changes)
- If Search Console crawl errors spike or Googlebot rate drops > 10%: disable Rules 3 and 4 immediately, escalate Rule 1 evaluation

### 3.4 Phase 1 Deliverables
- [ ] Bot Management enabled
- [ ] 7 WAF rules deployed (per sequence)
- [ ] 4 rate-limit rules deployed
- [ ] `infra/cloudflare-rules.md` documenting expressions + rationale
- [ ] Rollback runbook documented

**Owner:** Security
**Effort:** ~4 hours config, then 7 days monitoring/promotion
**Cost:** $20–$200/mo depending on plan tier
**Expected impact:** 40–70% reduction in bot pageviews, immediate Next.js compute savings

---

## 4. Phase 2 — Client Fingerprint Beacon + Trust Score (Days 8–14)

**Goal:** capture behavioral signal so trust score is informed by actual interaction, not just network metadata.

### 4.1 Files to ship

| Path | Purpose |
|---|---|
| `src/lib/trust-beacon.ts` | Inline beacon script (≤ 2KB minified) |
| `src/app/layout.tsx` | Mount beacon via `<Script strategy="afterInteractive">` |
| `src/app/api/trust/route.ts` | POST endpoint; verifies, persists, scores |
| `src/lib/trust-score.ts` | Pure scoring function (testable) |
| `src/middleware.ts` | Mint HMAC trust token per request |
| `src/lib/trust-kv.ts` | Cloudflare KV / Vercel KV adapter (read/write trust by fingerprint) |
| `src/components/HoneypotAnchor.tsx` | Hidden anchor component |
| `infra/honeypot-robots.txt` | `Disallow: /bot-trap` entry |

The beacon code is specified in `bot-traffic-forensic-analysis.md` §10 — use it verbatim, then minify.

### 4.2 Trust score V1 (deterministic, in `src/lib/trust-score.ts`)

Implement the formula from analysis §13. Persist by `(ja3, asn, ua_hash)` composite key in KV with 7-day TTL. Aggregate across sessions — repeat offenders accumulate evidence.

Bands:
- `>= 70` → trusted: full experience
- `40–69` → soft-suspicious: render content, hold ad bids, exclude from GA4 forward
- `20–39` → JS challenge on next nav
- `< 20` → shadow-block: cached HTML only, no DB writes, no ad calls

### 4.3 HMAC trust token

Edge middleware mints a token per HTML response:
```
token = base64url(
  HMAC_SHA256(secret_of_the_day,
              fingerprint_hash + ":" + issued_at_epoch_minute)
)
```
- Embedded as `<meta name="x-trust">` in the HTML
- Beacon reads it and sends with every `/api/trust` and `/api/event` POST
- Server rejects expired/invalid tokens
- Key rotates daily; previous-day key accepted with grace period

### 4.4 Ad-render gating

In ad component:
```ts
const trust = useTrustScore();   // hook reads /api/trust response or KV
const ready = await waitForInteraction(); // scroll OR mousemove OR 5s mobile viewport
if (trust >= 40 && ready) renderGPT();
```

Effect: no GPT calls for bot sessions → restores viewability, defends SSP trust scores.

### 4.5 Phase 2 Rollback
- Beacon is feature-flagged via env var `NEXT_PUBLIC_TRUST_BEACON=1`
- `/api/trust` returns 204 always (never blocks page render)
- If CWV INP regresses > 20ms: disable flag, keep `/api/trust` deployed for telemetry only

### 4.6 Phase 2 Deliverables
- [ ] Beacon shipped behind feature flag
- [ ] `/api/trust` endpoint live, writing to KV + BQ
- [ ] HMAC token rotation in middleware
- [ ] Honeypot anchor on every article layout
- [ ] Trust-score V1 unit-tested (≥ 90% branch coverage)
- [ ] CWV measured pre/post; INP delta documented

**Owner:** Frontend eng (beacon, components) + Backend eng (`/api/trust`, KV)
**Effort:** 4–5 dev-days
**Cost:** ≤ $50/mo for KV + extra logs

---

## 5. Phase 3 — Ad & Analytics Hardening (Days 12–18)

### 5.1 Server-side GA4 (Measurement Protocol)
- Configure server-side GTM (or direct MP calls)
- Forward events only when `trust_score >= 40 AND token_valid`
- Include `validation_code` in MP payload
- Internal "shadow" analytics in BigQuery captures all sessions (trusted + suspicious) for separate analysis

### 5.2 Prebid/GPT trust gating
- Wrap header-bidding init in trust check
- For `trust 40–69`: render direct-sold/house ads only (no programmatic)
- For `< 40`: no ads at all

### 5.3 Analytics filtering
- GA4 DebugView → Configure → exclude `trust_band=suspicious` events
- BigQuery analytics views always filter `WHERE trust_band IN ('trusted')` for editorial dashboards
- Maintain "raw + filtered" duality so we can always audit deltas

### 5.4 Phase 3 Deliverables
- [ ] Server-side GTM container deployed
- [ ] MP forwarding gated by trust score
- [ ] Prebid wrapped in trust check
- [ ] Editorial dashboards switched to filtered view
- [ ] Audit query showing raw vs filtered revenue/sessions

**Owner:** Ad eng + Analytics
**Effort:** 3 dev-days
**Expected impact:** SSP trust signal recovery in 2–6 weeks; RPM recovery 10–25%

---

## 6. Phase 4 — Detection Automation & ML (Days 18–35)

### 6.1 Anomaly alerting (deploy first; high ROI)

Scheduled BigQuery queries (every 15 min) emitting to PagerDuty / Slack:

| Alert | Condition | Severity |
|---|---|---|
| Bot-share spike | `bot_share_1h > 0.4` | P1 |
| Engagement EMD shift | `EMD(eng_hist_1h, eng_hist_baseline_30d) > 0.2` | P1 |
| JA3 collapse new cluster | New JA3 hash spanning >500 IPs in 1h | P2 |
| ASN volume spike | Single ASN req/min > 5σ above 7-day mean | P2 |
| Discover impressions drop | GSC daily impressions < 0.9 × 7-day avg | P1 |
| Googlebot crawl drop | Googlebot req rate < 0.9 × 14-day mean | P0 |
| CWV regression | p75 INP > baseline + 20ms | P0 |

### 6.2 ML v2 — Isolation Forest

- Feature vector (30 dims): bot_score, ja3 spread, asn flags, ua_consistency, ttfi, mouse_entropy, scroll_max, plugins, languages, request rate, path diversity, etc.
- Train nightly on last 14 days from BigQuery
- Deploy as Cloud Run inference endpoint OR materialized score in BQ
- Output: anomaly score per session, used as additional input to trust score V2

### 6.3 ML v3 — HDBSCAN cluster discovery
- Run weekly on JA3 + UA + path-sequence features
- Surface botnet "campaigns" as distinct clusters
- Top clusters get manual review and named operator labels ("Campaign-Alpha", "Campaign-Beta")
- New campaigns auto-generate WAF rules in a draft state for security review

### 6.4 Phase 4 Deliverables
- [ ] 7 anomaly alerts live with runbooks
- [ ] Isolation Forest trained, scoring nightly
- [ ] HDBSCAN clustering weekly report
- [ ] Auto-generated draft WAF rules pipeline

**Owner:** Data + Security
**Effort:** 6 dev-days for v2, +4 for v3
**Cost:** ~$100/mo BQ + Cloud Run

---

## 7. Phase 5 — Command-Center Dashboard Widgets (Days 25–40)

Add to existing `src/components/` (next to `PipelineWidget.tsx`, `EditorialWidget.tsx`, `TrendingWidget.tsx`):

| Component | Source | What it shows |
|---|---|---|
| `BotScoreHistogramWidget.tsx` | BQ Cloudflare | 24h distribution of BotScore, banded |
| `EngagementHistogramWidget.tsx` | BQ GA4 | engagement_time_msec histogram + baseline overlay; EMD score |
| `ASNWatchlistWidget.tsx` | BQ Cloudflare | Top 20 ASNs, req_per_ip, p50 bot score, sortable |
| `JA3CollapseWidget.tsx` | BQ Cloudflare | Top 10 JA3 hashes by IPs×ASNs product |
| `GSCDivergenceWidget.tsx` | BQ GA4 + GSC | per-page sessions vs clicks; z-score |
| `AdHealthWidget.tsx` | SSP APIs | RPM, viewability, IVT rate; 7-day trend |
| `HoneypotFeedWidget.tsx` | BQ Cloudflare | live tail of honeypot trips |
| `TrustFunnelWidget.tsx` | BQ trust events | sessions by trust band; conversion by band |

All widgets read from a single `/api/metrics/[widget]` route that runs the appropriate scheduled-cached BQ query (5-min cache).

### 7.1 Phase 5 Deliverables
- [ ] 8 widgets added to command-center
- [ ] `/api/metrics/*` routes with BQ caching
- [ ] Operator runbook for "what to do when widget shows red"

**Owner:** Frontend eng
**Effort:** 4 dev-days

---

## 8. Operational Runbooks

### 8.1 "Search Console clicks are dropping"
1. Check `Googlebot crawl rate` alert — if also dropping, suspect WAF over-blocking
2. Run §6.6 query — confirm GSC clicks vs GA4 sessions divergence direction
3. If WAF over-blocking: disable WAF Rules 3 and 4 (sec-ch-ua + DC-ASN), re-test
4. If real ranking drop: check Discover history, engagement-time histogram of GSC-referred traffic specifically
5. Notify SEO lead

### 8.2 "Bot share spiked"
1. Check JA3 collapse widget — is there a new cluster?
2. Check ASN watchlist — is a single ASN the source?
3. If yes: add to Rule 4 list in Log mode for 24h, then promote
4. If diffuse: tighten Rule 3 (sec-ch-ua) or lower BotScore challenge threshold from 30 → 40

### 8.3 "CWV INP regressed"
1. Check beacon-deploy timestamp vs regression timestamp
2. If correlated: disable `NEXT_PUBLIC_TRUST_BEACON` flag → revert
3. Profile beacon with Chrome perf trace
4. Common culprits: non-passive listeners, `sendBeacon` payload too large, mouse-entropy compute on hot path

### 8.4 "AdX/SSP throttling us"
1. Check viewability + IVT rate from SSP dashboards
2. Audit Prebid trust gating — are we still rendering ads to suspicious sessions?
3. Tighten gate: require `trust_score >= 50` for programmatic (vs 40)
4. Document outreach to SSP with our anti-fraud architecture (often unlocks throttle)

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Over-block real users in low-bandwidth markets | Medium | High | Stage every rule via Log → Challenge → Block; FP-rate gate < 0.5% before promote |
| Googlebot demotion due to WAF false-positive | Low–Med | Critical | Verified-bot Skip rule evaluates first; alert on crawl-rate drop |
| Beacon damages CWV | Low | Medium | Feature flag + p75 INP alert; pure inline, passive, sendBeacon-only |
| GA4 data divergence between raw and filtered | Certain | Low | Maintain both views, document delta; this is the point |
| Operator fatigue from too many alerts | Medium | Medium | P0/P1/P2 tiers; only P0–P1 pages, P2 to Slack channel |
| Bot operators adapt to our fingerprints | Certain (slow) | Medium | Quarterly recalibration; ML v3 surfaces new clusters |
| Privacy/legal: fingerprinting under GDPR | Low | Medium | Document fraud-prevention legitimate interest (Recital 47); update privacy policy |
| Ad partner doesn't recover RPM despite hardening | Med | Medium | Direct outreach with architecture doc; consider TAG certification |

---

## 10. Cost Summary (estimated monthly recurring)

| Item | Monthly |
|---|---|
| Cloudflare Business + Bot Mgmt | $200 |
| BigQuery storage + query | $150 |
| GA4 streaming export | $25 |
| Vercel/CF KV | $20 |
| Cloud Run (ML inference) | $50 |
| Misc (alerts, monitoring) | $30 |
| **Total** | **~$475/mo** |

Compare to expected ad revenue recovery for a fandom publication at this scale: payback in single-digit days if bot share is anywhere near our hypothesis.

---

## 11. Decision Gates

Do **not** advance to next phase without:

| Gate | From → To | Required |
|---|---|---|
| G1 | P0 → P1 | Anomaly report filled; histogram shape confirmed; top-5 JA3 + top-10 ASN identified |
| G2 | P1 → P2 | 7 days at current WAF posture with no SEO regression; bot share trend established |
| G3 | P2 → P3 | Beacon deployed without CWV regression; trust-score distribution shows clean bands |
| G4 | P3 → P4 | Server-side analytics live; raw-vs-filtered audit complete; SSP signals stable |
| G5 | P4 → ongoing | All 7 alerts firing correctly with documented runbooks |

---

## 12. What Ships First, in Order

```
Day 1   - Cloudflare Logpush → BQ
Day 1   - GA4 → BQ export
Day 1   - Search Console → BQ
Day 2   - Run diagnostic queries, fill anomaly report
Day 3   - DECISION GATE G1
Day 4   - WAF Rule 1 (verified-bot Skip, always-on)
Day 4   - WAF Rule 2 (static signatures, Log → Block in 24h)
Day 5   - WAF Rule 3 (sec-ch-ua, Log)
Day 5   - WAF Rule 4 (DC ASN, Log)
Day 5   - WAF Rule 5 (honeypot, Block)
Day 6   - Rate-limit rules (all 4)
Day 7   - WAF Rules 3,4 → Managed Challenge
Day 8   - Beacon code shipped behind flag (off)
Day 9   - /api/trust + KV + middleware HMAC
Day 10  - Beacon flag enabled at 10% traffic
Day 11  - DECISION GATE G2
Day 11  - Beacon to 100%; CWV measured
Day 12  - Ad-render gating
Day 13  - WAF Rule 6 (JA3 collapse)
Day 14  - DECISION GATE G3
Day 15  - Server-side GA4 + Prebid gating
Day 17  - Filtered analytics dashboards
Day 18  - DECISION GATE G4
Day 19  - 7 alerts live
Day 22  - Isolation Forest v2
Day 28  - Command-center widgets (8)
Day 32  - HDBSCAN cluster discovery
Day 35  - DECISION GATE G5
Day 35+ - Quarterly review cadence established
```

---

## 13. Owners & Single Points of Contact

| Area | Owner |
|---|---|
| Cloudflare config | Security lead |
| BigQuery / SQL | Data eng lead |
| Beacon + frontend | Frontend lead |
| `/api/trust` + scoring | Backend lead |
| Ad pipeline + Prebid | Ad eng lead |
| Search Console + SEO impact | SEO lead |
| Sign-off on user-facing changes | Editorial |

Weekly sync: 30 min, Wednesdays, until G5 reached.

---

## 14. Out of Scope (Explicit)

To prevent scope creep:

- **No site-wide CAPTCHA.** Only on `BotScore < 20` and only on non-article paths.
- **No JS-only article rendering.** Articles must remain SSR-readable for SEO.
- **No User-Agent-only blocking** beyond Rule 2's narrow signature list.
- **No third-party paid bot mitigation vendor** in this plan. Revisit at G5 if defense is insufficient.
- **No proactive de-listing of AI crawlers** at WAF before robots.txt declares it; lead with the standard.
- **No changes to existing editorial widgets** in this plan; new widgets only.

---

*This plan is the execution doc. The forensic analysis (`docs/bot-traffic-forensic-analysis.md`) is the why. Both must move together: every rule's threshold ties back to a metric in the analysis; every phase has a query in §6 of the analysis.*
