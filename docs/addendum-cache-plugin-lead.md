# Addendum — Cache-Plugin / Used-CSS Crawler Lead

**Date:** 2026-05-13
**Trigger:** Operator (developer behind the cache plugin in use on FandomWire) reports the suspect traffic correlates with **his cache plugin update**. The plugin generates **Used CSS** by spawning **Puppeteer** to crawl every page from **Vietnam-based servers**. Architecture is described as similar to **FlyingPress** (Gijo Varghese's plugin). Operator's own assessment: **not an attack** — pattern is consistent with a benign optimization crawler.

This re-anchors the analysis. Confidence the bulk of the anomaly is malicious drops from **~0.92 to ~0.35**. Confidence it is **first-party cache-plugin Puppeteer crawl traffic** rises to **~0.7**, pending IP/UA confirmation.

---

## 1. Why this fits the symptoms

| Symptom | Cache-plugin Puppeteer crawler fit |
|---|---|
| ~0.98s engagement | Perfect — Puppeteer pages render, `gtag` fires, then `browser.close()` is called as soon as the CSS extractor finishes coverage analysis. Coverage in Puppeteer takes ~700–1500ms per page. |
| Distributed IPs | Cloud crawlers rotate egress IPs across a /24 or /22 in Vietnam datacenters |
| JS executes (GA4 fires) | Headless Chrome executes JS by design; Coverage API needs JS to run |
| No scroll / mouse / keyboard | Puppeteer doesn't synthesize interaction during CSS coverage |
| No ad rendering | Many cache crawlers block `/gpt.js`, `/ads`, `/analytics` to speed crawl — but some don't, which is why GA4 still gets hit |
| Traffic spike after plugin update | Plugin re-generates Used CSS for the entire site after an update or a settings change |
| Pattern fits a fixed user-agent / JA3 | Single Puppeteer build → single JA3, consistent UA string |

This is a **textbook "benign optimization crawler polluting analytics"** scenario. It's a known pain point for high-traffic publishers using FlyingPress / WP Rocket RUCSS / Perfmatters Used-CSS / NitroPack / LiteSpeed Critical CSS / Autoptimize.

---

## 2. Revised threat picture

| Layer | Old estimate | New estimate |
|---|---|---|
| Cache-plugin Puppeteer crawler (first-party but mis-attributed in GA4) | not considered | **~60–75% of anomaly** |
| Headless scrapers (third-party, for content/LLM harvesting) | 40–60% | **~10–20%** |
| Residential-proxy bots / engagement fraud | 20–30% | **~5–10%** |
| AI crawlers | 10–20% | **~5–10%** |
| Real low-quality referral | residual | residual |

The protection plan still ships — third-party scrapers and AI crawlers are still real, just smaller than initially estimated — but the **first-line fix is filtering and tagging, not blocking.**

---

## 3. Critical: do NOT block this crawler

Blocking the cache plugin's Puppeteer crawler in the WAF would:
- Stop Used-CSS regeneration → site serves bloated CSS → **CWV INP/LCP regression** (the opposite of what the plugin exists to prevent)
- Stop critical CSS updates → article pages render with FOUC
- Repeatedly retry from new IPs (cache plugins retry aggressively), inflating WAF logs

WAF Rule 4 (DC ASN block) in the protection plan **must exclude the cache-plugin egress ASNs**. See §5 below.

---

## 4. Confirmation queries (priority before any protection-plan rule ships)

Run these first — they confirm or refute the cache-plugin hypothesis in minutes.

### 4.1 UA fingerprint check
```sql
SELECT
  ClientRequestUserAgent,
  COUNT(*) AS req,
  COUNT(DISTINCT ClientIP) AS ips,
  COUNT(DISTINCT ClientASN) AS asns,
  STRING_AGG(DISTINCT CAST(ClientASN AS STRING), ',' LIMIT 5) AS sample_asns,
  AVG(BotScore) AS avg_bot_score
FROM `fandomwire_cloudflare.http_requests`
WHERE EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 48 HOUR)
  AND (
    LOWER(ClientRequestUserAgent) LIKE '%headlesschrome%'
    OR LOWER(ClientRequestUserAgent) LIKE '%puppeteer%'
    OR LOWER(ClientRequestUserAgent) LIKE '%flyingpress%'
    OR LOWER(ClientRequestUserAgent) LIKE '%wprocket%'
    OR LOWER(ClientRequestUserAgent) LIKE '%critical%'
    OR LOWER(ClientRequestUserAgent) LIKE '%usedcss%'
    OR LOWER(ClientRequestUserAgent) LIKE '%nitropack%'
    OR LOWER(ClientRequestUserAgent) LIKE '%perfmatters%'
    OR LOWER(ClientRequestUserAgent) LIKE '%litespeed%'
  )
GROUP BY 1
ORDER BY req DESC;
```

Expected if the lead is correct: a small set of UAs producing many requests from a small set of ASNs.

### 4.2 Vietnamese-ASN concentration
```sql
SELECT
  ClientASN,
  ClientASNDescription,
  COUNT(*) AS req,
  COUNT(DISTINCT ClientIP) AS ips,
  COUNT(DISTINCT ClientRequestPath) AS unique_paths,
  AVG(BotScore) AS avg_bot
FROM `fandomwire_cloudflare.http_requests`
WHERE EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 48 HOUR)
  AND ClientCountry = 'VN'
GROUP BY 1, 2
ORDER BY req DESC;
```

Suspect ASNs to watch in Vietnam:
- `AS131429` — Mobifone
- `AS45899` — VNPT
- `AS7552` — Viettel
- `AS18403` — FPT Telecom
- `AS135905` — VNPT-AS-VN
- `AS24086` — Viettel datacenter
- Plus US/SG cloud egress used by Vietnamese ops: AS14061 (DigitalOcean SG), AS16509 (AWS ap-southeast-1)

If 1–3 ASNs in VN account for >50% of the anomaly volume with a tiny UA + JA3 set, that's confirmation.

### 4.3 Path-coverage signature
A Used-CSS crawler walks **every page exactly once** in a tight time window. A scraper walks selectively and repeatedly.
```sql
SELECT
  ClientIP,
  ClientASN,
  COUNT(DISTINCT ClientRequestPath) AS distinct_paths,
  COUNT(*) AS req,
  SAFE_DIVIDE(COUNT(*), COUNT(DISTINCT ClientRequestPath)) AS repeat_factor,
  MIN(EdgeStartTimestamp) AS first_seen,
  MAX(EdgeStartTimestamp) AS last_seen,
  TIMESTAMP_DIFF(MAX(EdgeStartTimestamp), MIN(EdgeStartTimestamp), MINUTE) AS span_min
FROM `fandomwire_cloudflare.http_requests`
WHERE EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 48 HOUR)
  AND ClientCountry = 'VN'
GROUP BY 1, 2
HAVING distinct_paths > 100 AND repeat_factor < 1.5
ORDER BY req DESC;
```

A few IPs hitting hundreds-to-thousands of distinct paths with `repeat_factor ≈ 1.0` over a short span → **CSS crawler signature**, not a scraper.

### 4.4 Coordinate with the plugin developer
Ask "One Man Army" directly for:
- The egress IP range or ASN(s) the Puppeteer fleet uses
- The exact UA string the crawler sends (often customizable in plugin settings)
- An optional custom request header (e.g. `X-CacheGen: 1`) the plugin could send so we can tag traffic explicitly — this is the cleanest possible solution and most cache plugins support adding a header

A single trusted header turns this from a forensics problem into a one-line filter.

---

## 5. Revised actions — what changes vs. the protection plan

### 5.1 Add an allowlist branch (highest priority)
Insert a new WAF rule **above** all challenge rules:

```
# Rule 1.5 — Cache-plugin trusted crawler (Skip)
(
  ip.geoip.asnum in { <confirmed cache-plugin ASNs> }
  and http.user_agent contains "<confirmed crawler UA token>"
)
or any(http.request.headers["x-cachegen"][*] eq "<shared-secret>")
```
Action: **Skip** (let it through; do not challenge; do not rate limit).

### 5.2 Tag it everywhere (don't pollute analytics)

**Cloudflare → Workers** (cheapest): inject a header `cf-fw-trust: cachegen` on responses if the request matches the cache-plugin signature. Then downstream filters everywhere use that single source of truth.

**GA4 filtering** (most important — eliminates the symptom):
- Server-side GTM: if `cf-fw-trust = cachegen` → **drop** the event; do not forward to GA4
- Or: GA4 Admin → Data Streams → Configure tag settings → Define internal traffic → add the cache-plugin IP range → mark as "internal" → exclude from reports

This single change is what makes the engagement-time metric recover. The crawler is real and necessary; it just shouldn't appear in your reader analytics.

**Search Console:** unaffected — Googlebot is verified separately.

**Ad pipeline:** the cache-plugin crawler should already not be loading ads (since it's just measuring CSS coverage). If it is, gate by header in §5.1.

### 5.3 Negotiate with the plugin

Ask the plugin developer to:
- Send a recognizable header (`X-CacheGen: 1` or similar)
- Send a recognizable UA suffix
- Skip the GA4 endpoint (`/g/collect`) at fetch time
- Run regeneration in off-peak hours (configurable in most plugins; FlyingPress and WP Rocket both support cron-based scheduling)
- Honor robots.txt `User-agent: <cache-plugin-name>` directives if a regen storm needs to be paused

### 5.4 Lower WAF aggressiveness on the protection plan
- **Rule 3 (sec-ch-ua):** keep, still high-value
- **Rule 4 (DC ASN):** **must exclude Vietnam cache-plugin ASNs** by ID; otherwise it breaks Used-CSS generation
- **Rule 6 (JA3 collapse):** verify the top JA3 before blocking; if it's the cache plugin, allowlist it instead
- **Rate limits:** the cache-plugin crawler can plausibly hit > 100 req/min/IP during a regen cycle; raise the per-IP limit for allowlisted ASNs to 1000 req/min, or skip them entirely

### 5.5 Keep the rest of the plan
The other ~10–25% of suspicious traffic that isn't the cache plugin is still real third-party scrapers and AI crawlers. Phases 2–5 of the protection plan remain valuable:
- Beacon + trust score: still useful, will now also clearly distinguish cache-plugin sessions from human sessions (zero interaction, single UA, fixed JA3)
- Server-side analytics: still important; the cache-plugin filter rides on top of it
- Anomaly alerting: still important — alerts on **new** anomalies are still needed; cache-plugin baseline gets folded in

---

## 6. Caveats

- This is **second-hand intel** from the plugin developer's chat. We still need to confirm by running §4 queries. People are sometimes wrong about their own products.
- "Attack pattern aaya nahi hai" is a useful prior but not proof. A sophisticated attacker can co-exist with the cache-plugin crawler and hide behind it. **Run the queries; don't take anyone's word for it, including mine.**
- Cache plugins themselves can be misconfigured — if regeneration is firing on every cache miss instead of on a schedule, the plugin itself becomes the problem and needs to be reconfigured, not whitelisted.
- If the volume is implausibly high for "site-wide CSS regen" (e.g., millions/day for a finite article catalog), there is **still a bot problem on top** of the cache plugin.

---

## 7. Revised top-of-funnel action list

```
DAY 1 (highest priority):
  1. Run query §4.1 + §4.2 + §4.3 — confirm cache-plugin signature
  2. Get explicit IP/UA/header from plugin developer
  3. Add GA4 internal-traffic filter for cache-plugin IPs   ← biggest single win
  4. Add Worker header-injection rule for cache-plugin signature
  5. Verify: does engagement-time histogram clean up after the GA4 filter?

DAY 2–3:
  6. Negotiate header + scheduling with plugin developer
  7. Decide what % of remaining anomaly is real (re-run §6 queries from analysis doc)
  8. Resume protection plan from Phase 1 with ASN exclusion list updated

DAY 4+: continue with the protection plan as-written.
```

---

*This addendum supersedes Phase 0 → 1 sequencing in the main protection plan when (and only when) §4 queries confirm the cache-plugin signature. If §4 returns negative — i.e., the suspicious volume does not concentrate in cache-plugin ASNs/UAs — disregard this addendum and execute the original plan unchanged.*
