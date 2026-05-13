# FandomWire.com — Suspicious Low-Engagement Traffic Forensic Investigation

**Status:** Working hypothesis report (no live log access yet — see §3 for the access we need to confirm)
**Author:** Anti-fraud / ad-tech bot detection engineering
**Scope:** ~0.98s average engagement time, distributed-IP pageview activity, near-zero interaction
**Posture:** Treat all analytics data as adversarial until proven otherwise

---

## 1. Executive Summary

The reported pattern — **massive pageview volume, sub-1s engagement, geographically scattered IPs, near-zero interaction** — is **not consistent with "low-quality real users."** Human readers, even disengaged ones, do not cluster at ~1.0s; that number is a **fingerprint of automation**. Real human bounces follow a long-tail distribution centered around 8–25s with high variance. A point-mass at ~0.98s implies an actor that:

1. Loads the page (so GA4 fires `page_view`)
2. Waits a fixed `setTimeout` (~1000 ms — common default in headless harnesses and `engagement_time_msec` poisoning kits)
3. Closes or navigates

This is the classic signature of one of three things, in order of prior probability for a high-traffic celebrity/fandom publication:

| # | Hypothesis | Prior | Why it fits |
|---|---|---|---|
| **H1** | **Headless/automated scrapers** (Puppeteer, Playwright, undetected-chromedriver, Selenium-stealth) feeding LLM training pipelines, content aggregators, or rival sites | **High (~45%)** | Fandom/celebrity content is heavily scraped; fits "JS executes → analytics fires → no interaction" |
| **H2** | **Residential-proxy traffic bots** simulating "real" users (Bright Data / IPRoyal / 922 S5 networks) for **traffic-exchange, CPM ad fraud, or PBN warm-up** | **High (~30%)** | Explains IP distribution, geo spread, and CTR/engagement anomaly |
| **H3** | **Click-farm / engagement-poisoning attack** (SEO negative, competitor sabotage, or "boost" service gone wrong) | **Medium (~15%)** | Plausible if you recently outranked a competitor or saw a Discover spike |
| H4 | AI crawler traffic (GPTBot, ClaudeBot, PerplexityBot, Bytespider, Amazonbot, Applebot-Extended) misclassified as users | Medium-low (~7%) | Most respect UA strings; mis-attribution happens when they spoof or proxy |
| H5 | Invalid ad traffic (IVT) driving inventory laundering | Low–Medium (~3%) | Possible if you sell programmatic and someone is arbitraging your domain via spoofed `ads.txt` |

The probability that this is **purely legitimate low-quality users is near zero**, because legitimate low-quality traffic does not produce a tight engagement-time mode at ~1s. That signal alone is a strong (>0.85) prior for automation.

**Confidence score that some non-trivial fraction of traffic is bot/automated: 0.92**
(will revise up or down once we see UA distribution, ASN clustering, and TLS JA3/JA4 fingerprints — see §3.)

---

## 2. Why 0.98s Is the Smoking Gun

GA4's `engagement_time_msec` is measured **on the client**, fired via `sendBeacon` on visibility change / page unload. It is **trivial to poison** by:

- A headless browser running `page.goto(url); await sleep(1000); browser.close();`
- A bot that loads the DOM, waits for `gtag` to fire `page_view`, then immediately closes the tab
- A traffic-exchange script that injects `<iframe src="fandomwire.com">` and tears it down after a fixed timer

Real human distributions of engagement time have:

- Mean: **30–90s** for a content site
- Median: **15–40s**
- A **fat right tail** (engaged readers spending minutes)
- A bounce mode around **5–15s** (people who skim the headline and leave)

**A 0.98s mean is statistically incompatible with the bounce-mode of a real audience.** It is a programmatic mean — the central limit theorem applied to a `setTimeout(close, 1000)` with small jitter.

> **Action #1:** Pull GA4 `engagement_time_msec` as a **histogram, not an average.** A real audience produces a bimodal or long-tail histogram. A bot audience produces a delta function with stddev < 200ms. The shape of the histogram alone confirms or refutes the bot hypothesis with very high confidence.

---

## 3. Forensic Data Collection — What We Need

Confidence will jump once we have:

### 3.1 Cloudflare (Logpush → R2 / BigQuery / S3)
- `ClientIP`, `ClientASN`, `ClientCountry`
- `ClientRequestUserAgent`, `ClientRequestPath`, `ClientRequestReferer`
- `ClientTCPRTTMs`, `ClientSSLProtocol`, `ClientSSLCipher`
- **`ClientRequestHTTPHost` and `EdgeStartTimestamp`** (request timing analysis)
- **`BotScore`** (Cloudflare Bot Management — single most useful field; range 1–99, where ≤30 is "likely bot")
- **`BotScoreSrc`** (`Heuristics`, `MachineLearning`, `Verified Bot`, etc.)
- **`JA3Hash` / `JA4`** (TLS client fingerprints)
- `WAFAttackScore`, `EdgeResponseStatus`

### 3.2 GA4 (BigQuery export — non-negotiable)
- `events_*` table with `engagement_time_msec`, `user_pseudo_id`, `ga_session_id`
- `device.*`, `geo.*`, `traffic_source.*`, `collected_traffic_source.*`
- Custom events for `scroll`, `click`, `view_search_results`

### 3.3 Origin server access logs (Next.js / Vercel / nginx)
- Timing, byte counts, referer, UA, full path including query strings (UTM tampering check)

### 3.4 Client-side fingerprint signal (needs to be deployed — see §10)
- `navigator.webdriver`, `navigator.languages.length`, `navigator.plugins.length`
- WebGL vendor/renderer, canvas hash, AudioContext hash
- `screen.width × screen.height`, `devicePixelRatio`
- Mouse-move entropy (Shannon entropy of x/y deltas)
- Time-to-first-interaction
- Hidden honeypot trip flag

### 3.5 Search Console
- Impressions/clicks/CTR vs. GA4 sessions per page — divergence is diagnostic
- Discover impressions vs. analytics pageviews

Until we have **at least Cloudflare BotScore + ASN + JA3 + GA4 engagement histogram**, every conclusion below is hypothesis-grade. With those four, confidence approaches certainty.

---

## 4. Hypothesis Triage — What Each Class of Attacker Looks Like

| Indicator | Headless scraper (H1) | Residential proxy (H2) | Click farm (H3) | AI crawler (H4) | IVT/ad fraud (H5) |
|---|---|---|---|---|---|
| BotScore | Low (1–30) | **Medium (30–70)** ← evasive | Variable | Verified or low | Low/medium |
| ASN | **DC** (AWS, OVH, Hetzner, DigitalOcean, Linode, Vultr, M247) | **ISP/residential** (Comcast, Telkom, Reliance, mobile carriers) | Mobile/residential, clustered geo | Vendor-owned (Google, OpenAI, Anthropic, Bytedance) | Mixed; often DC behind proxies |
| Geo | Globally distributed but DC-heavy | Globally distributed, **realistic mobile/residential mix** | **Concentrated** (PH, VN, BD, ID, NG, EG) | US/EU primarily | Mixed |
| UA | Often outdated Chrome (`117`, `120`) or `HeadlessChrome` leaked | **Up-to-date Chrome, real-looking** | Real mobile UAs | Vendor-declared or spoofed | Spoofed |
| `navigator.webdriver` | `true` if not patched | `false` (patched) | `false` (real browsers) | N/A (no JS) | Varies |
| JA3 entropy | **Low** — handful of fingerprints across thousands of IPs | Medium | High (real devices) | Distinct per vendor | Mixed |
| Engagement time | **~1s constant** | 1–3s **with jitter** | 1–10s | 0 (no JS) or N/A | Programmatic |
| Mouse entropy | **0** | **0 or scripted** | Low but nonzero | N/A | Usually 0 |
| Pages/session | 1.0 | 1.0–1.2 | 1–2 | 1 + crawl | 1 |
| Referer | Empty / spoofed `google.com` | Empty / spoofed | Often Facebook | Empty | Spoofed |
| `sec-ch-ua` headers | **Missing or inconsistent with UA** | Consistent | Consistent | Consistent | Inconsistent |
| Cookie persistence | None | Sometimes | Sometimes | None | None |
| Loads ads | **No** (often blocks `/ads`, `/gpt.js`) | **Sometimes yes** (ad fraud) | Yes | No | **Yes — and clicks** |

**Discriminator queries** (below in §6) will collapse this matrix to one or two boxes.

---

## 5. Confirmed Indicators vs. Hypotheses

### 5.1 Confirmed (from your symptom description alone)
1. **Engagement-time anomaly is real** — 0.98s mean is mathematically incompatible with human distributions
2. **Activity is JS-capable** — GA4 fires, so this is not a `curl` scraper; it's a browser or headless browser
3. **IP distribution is wide** — rules out single-source DoS; consistent with botnet, proxy pool, or distributed AI crawler

### 5.2 Strong hypotheses pending data
1. **DC-ASN concentration** — likely (testable via Cloudflare ASN aggregation)
2. **JA3 fingerprint collapse** — likely (a handful of TLS fingerprints across thousands of IPs)
3. **UA/`sec-ch-ua` mismatch** — likely (stealth libraries often miss client hints)
4. **No real interaction events** — likely (scroll_depth, click events should be ~0)
5. **Ad impression decoupling** — likely (pageviews up, ad CPMs down → fraudulent inventory)

### 5.3 Hypotheses that would surprise me
- A single nation-state actor (this looks commercial, not targeted espionage)
- A real DDoS (pattern is too slow and JS-heavy; DDoS would saturate edge, not analytics)

---

## 6. Investigation Queries

### 6.1 GA4 (BigQuery) — engagement-time histogram by traffic source

```sql
-- Histogram of engagement_time_msec bucketed in 250ms bins
-- Compare each traffic source to "google / organic" (your trusted baseline)
WITH sessions AS (
  SELECT
    user_pseudo_id,
    (SELECT value.int_value FROM UNNEST(event_params) WHERE key='ga_session_id') AS session_id,
    traffic_source.source AS source,
    traffic_source.medium AS medium,
    geo.country,
    device.category,
    SUM((SELECT value.int_value FROM UNNEST(event_params) WHERE key='engagement_time_msec')) AS eng_ms
  FROM `fandomwire.analytics_XXXXXX.events_*`
  WHERE _TABLE_SUFFIX BETWEEN
        FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 14 DAY))
    AND FORMAT_DATE('%Y%m%d', CURRENT_DATE())
  GROUP BY 1,2,3,4,5,6
)
SELECT
  source, medium, country, device.category AS dev,
  CAST(FLOOR(eng_ms / 250) * 250 AS INT64) AS bucket_ms,
  COUNT(*) AS sessions
FROM sessions
WHERE eng_ms IS NOT NULL
GROUP BY source, medium, country, dev, bucket_ms
ORDER BY source, bucket_ms;
```

**What to look for:** a delta-function spike in the `750–1250 ms` bucket for a specific source/country combo is your bot population.

### 6.2 GA4 — interaction-free session ratio

```sql
SELECT
  traffic_source.source,
  geo.country,
  device.category,
  COUNT(DISTINCT CONCAT(user_pseudo_id, CAST((SELECT value.int_value FROM UNNEST(event_params) WHERE key='ga_session_id') AS STRING))) AS sessions,
  SUM(CASE WHEN event_name IN ('scroll','click','user_engagement','view_search_results') THEN 1 ELSE 0 END) AS interactions,
  SAFE_DIVIDE(SUM(CASE WHEN event_name IN ('scroll','click') THEN 1 ELSE 0 END),
              COUNT(DISTINCT CONCAT(user_pseudo_id, CAST((SELECT value.int_value FROM UNNEST(event_params) WHERE key='ga_session_id') AS STRING)))) AS interactions_per_session
FROM `fandomwire.analytics_XXXXXX.events_*`
WHERE _TABLE_SUFFIX BETWEEN '20260429' AND '20260513'
GROUP BY 1,2,3
HAVING sessions > 500
ORDER BY interactions_per_session ASC;
```

Sources with **>1000 sessions and <0.05 interactions/session** are bot-heavy with very high confidence.

### 6.3 Cloudflare Logpush — ASN clustering

```sql
SELECT
  ClientASN,
  ClientASNDescription,
  ClientCountry,
  COUNT(*) AS requests,
  COUNT(DISTINCT ClientIP) AS unique_ips,
  AVG(BotScore) AS avg_bot_score,
  APPROX_QUANTILES(BotScore, 100)[OFFSET(50)] AS p50_bot_score,
  COUNT(DISTINCT JA3Hash) AS unique_ja3,
  SAFE_DIVIDE(COUNT(*), COUNT(DISTINCT ClientIP)) AS req_per_ip
FROM `cloudflare.logs.http_requests`
WHERE EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND ClientRequestHost = 'fandomwire.com'
GROUP BY 1,2,3
HAVING requests > 1000
ORDER BY requests DESC;
```

**Red flags:**
- `unique_ja3 = 1` across thousands of IPs → **scripted client**
- `req_per_ip < 3` and `requests > 50k` → **proxy pool**
- ASN owners like `Amazon`, `Google Cloud`, `Hetzner`, `OVH`, `DigitalOcean`, `Linode`, `Vultr`, `M247`, `Choopa`, `Contabo`, `Akamai Linode`, `Latitude.sh`, `Servers.com` → **datacenter masquerading as users**
- ASN owners listed as `Bright Data`, `Oxylabs`, `Smartproxy`, `IPRoyal`, `NetNut`, `Soax`, `Pacific Rack` → **residential proxy networks**

### 6.4 Cloudflare — JA3/JA4 fingerprint collapse

```sql
SELECT
  JA3Hash,
  COUNT(*) AS requests,
  COUNT(DISTINCT ClientIP) AS unique_ips,
  COUNT(DISTINCT ClientASN) AS unique_asns,
  ANY_VALUE(ClientRequestUserAgent) AS sample_ua,
  AVG(BotScore) AS avg_bot
FROM `cloudflare.logs.http_requests`
WHERE EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY JA3Hash
HAVING unique_ips > 100
ORDER BY requests DESC
LIMIT 50;
```

**A single `JA3Hash` spanning >1000 IPs across >50 ASNs is essentially proof of a coordinated scraper or proxy pool** — a real population of users produces a long tail of JA3 hashes.

### 6.5 UA / Client Hints consistency

```sql
SELECT
  ClientRequestUserAgent,
  -- Chrome 90+ MUST send these client hints over HTTPS
  COUNTIF(`cf-ch-ua` IS NULL) AS missing_ch_ua,
  COUNT(*) AS total,
  SAFE_DIVIDE(COUNTIF(`cf-ch-ua` IS NULL), COUNT(*)) AS pct_missing
FROM `cloudflare.logs.http_requests`
WHERE ClientRequestUserAgent LIKE '%Chrome/%'
  AND EdgeStartTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY 1
HAVING total > 500 AND pct_missing > 0.5;
```

Any UA claiming Chrome ≥ 90 that **fails to send `sec-ch-ua`** over HTTPS is **lying about being Chrome**. This is one of the cheapest, highest-precision bot signals available.

### 6.6 GA4 vs. Search Console divergence

Pull weekly GA4 sessions by landing page and join against Search Console clicks for the same page. **Sessions much greater than Search Console clicks + known referral sources = injected traffic.** This is also how you detect direct-traffic inflation.

---

## 7. Behavioral Anomaly Report (template — fill once data lands)

```
SECTION 1: Volume anomaly
  - Baseline sessions/day (pre-incident): __
  - Current sessions/day: __
  - Excess: __ %
  - Period of anomaly: __

SECTION 2: Engagement collapse
  - Pre-incident mean engagement: __ s
  - Current mean: 0.98 s
  - Histogram shape: [bimodal human / delta function bot / mixed]
  - Stddev: __ ms  (bot signature: < 200)

SECTION 3: Interaction collapse
  - scroll events / session: __  (human baseline 3–8)
  - click events / session: __   (human baseline 0.3–1.5)

SECTION 4: Source attribution
  - Top suspicious sources:
    1. (direct) / (none) — __ sessions, __ % of total
    2. __  — __ sessions
    3. __  — __ sessions

SECTION 5: ASN attribution
  - Top suspicious ASNs:
    1. AS____ (Provider) — __ requests, __ IPs, BotScore p50 __
    2. ...

SECTION 6: Fingerprint collapse
  - Top JA3 hashes by spread:
    1. __ — __ IPs across __ ASNs

SECTION 7: Ad-side impact
  - Ad impressions/session: __ (vs baseline __)
  - eCPM: __ (vs baseline __)
  - Estimated IVT-driven loss: $__
```

---

## 8. Financial & SEO Impact Model

### 8.1 Ad revenue
For a media site at this scale, common impacts:

| Loss vector | Mechanism | Magnitude |
|---|---|---|
| **Diluted RPM** | Bot pageviews without ad impressions reduce session RPM and crash auctions | Typically 10–35% RPM hit if >20% of sessions are non-ad-loading bots |
| **SSP throttling** | Google AdX, Magnite, Index, Pubmatic auto-throttle inventory with low viewability + high invalid rate | Inventory shadow-banned in 2–6 weeks |
| **MFA/IVT flag** | Repeated invalid traffic can get the domain flagged in `sellers.json` and Trustworthy Accountability Group reports | Reputational; hard to reverse |
| **Direct IVT clawback** | Programmatic partners issue makegoods/clawbacks | 1–3 month revenue retroactive risk |

Order-of-magnitude estimate for a fandom/celebrity publication: **if 30% of traffic is automation and the bot share avoids ads, expect a 15–25% net revenue drag** plus medium-term SSP risk.

### 8.2 SEO / Google Discover
This is where it gets dangerous and where most publishers underreact:

- **Chrome UX Report (CrUX)** is fed by real Chrome instances. Headless Chrome / Puppeteer **also feeds CrUX** unless explicitly disabled. Bot sessions with zero scroll + 1s engagement degrade **Largest Contentful Paint statistics, INP, and engagement signals** that Google uses for Discover ranking.
- **Discover quality model** is opaque but is widely believed to use post-click engagement (dwell, bounce-back). A flood of 1s sessions on Discover-referred articles can **drop Discover impressions by 30–80% within days.**
- **Crawl budget** is finite. If headless scrapers are hammering category pages, Googlebot may experience 5xx/slow responses and reduce crawl frequency.

**SEO risk grade: HIGH.** Search Console divergence (§6.6) is the canary.

### 8.3 Server & cost
Bot traffic that triggers full Next.js renders (not cached) burns compute, edge bandwidth, and database queries. On Vercel/Cloudflare, this directly costs money via function invocations and edge requests.

---

## 9. Mitigation Strategy — Priority Order

### P0 — Visibility (do this week)
1. **Turn on Cloudflare Logpush** to BigQuery/R2 with `BotScore`, `JA3Hash`, `ClientASN`. Without this, every other step is blind.
2. **Enable GA4 → BigQuery export** (free tier is sufficient for ad-hoc).
3. **Deploy a client-side fingerprint beacon** (see §10) — a 2KB JS that captures interaction telemetry and POSTs once per session.
4. **Run the queries in §6** and complete the §7 report. This converts "0.92 confidence" into "1.00 confidence."

### P1 — Edge filtering (week 1–2)
Apply at Cloudflare, **not in app code** (avoid wasting Next.js compute on bots):

5. **Cloudflare Bot Management** enabled (Super Bot Fight Mode at minimum if Enterprise unavailable). Block `BotScore <= 5`, JS Challenge `BotScore <= 30`.
6. **Block known DC ASNs** masquerading as users — see §11 rules.
7. **Verified-bot allowlist** — explicitly allow Googlebot, Bingbot, Applebot, GPTBot if you want them; everything else claiming to be a search bot gets challenged.
8. **`sec-ch-ua` consistency rule** — challenge any Chrome UA missing client hints.

### P2 — Behavioral validation (week 2–4)
9. **Time-to-first-interaction gate** — record TTFI client-side; if it doesn't fire within 60s, demote session in your analytics and ad stack.
10. **Honeypot links** — invisible link to `/bot-trap`, blocked in robots.txt, no `nofollow` — any IP hitting it is silently shadow-banned (high precision, ~zero false positive).
11. **Server-side GA4 validation** — move conversions to server-side GTM with secret tokens, so attackers can't poison analytics by replaying client beacons.
12. **Ad slot gating** — only render GPT/Prebid after a real interaction signal (scroll OR mouse OR 5s viewport visibility on mobile). This protects ad inventory quality and ad-stack trust signals.

### P3 — Detection automation (week 3–8)
13. **Behavioral scoring engine** — see §13.
14. **Anomaly alerting** — see §15.
15. **Quarterly recalibration** — bot operators adapt; thresholds drift.

### P4 — Strategic (ongoing)
16. Subscribe to a **bot fingerprint feed** (Cloudflare Bot Management ML or Imperva / DataDome / HUMAN feed if budget allows).
17. **Threat intel sharing** with peer publishers (BuzzFeed, Polygon, IGN's anti-fraud teams maintain informal IOC shares).

---

## 10. Client-Side Fingerprint Beacon — Implementation

Drop into `src/app/layout.tsx` as a small inline script (kept tiny to avoid CWV impact). Posts once on `visibilitychange === 'hidden'` via `sendBeacon`. No external dependency. **All fingerprinting is GDPR-acceptable as "fraud prevention" legitimate interest** (Recital 47) — document this in your privacy policy.

```ts
// /api/trust collects the beacon server-side; trust score computed in §13.
(function () {
  const t0 = performance.now();
  let firstInteraction: number | null = null;
  let mouseDeltaSum = 0, mouseSamples = 0, lastX = 0, lastY = 0;
  let scrollMax = 0, scrollSamples = 0;
  let keyCount = 0, touchCount = 0;
  let honeypotTripped = false;

  const onMove = (e: MouseEvent) => {
    if (firstInteraction === null) firstInteraction = performance.now() - t0;
    if (mouseSamples > 0) mouseDeltaSum += Math.hypot(e.clientX - lastX, e.clientY - lastY);
    lastX = e.clientX; lastY = e.clientY; mouseSamples++;
  };
  const onScroll = () => {
    if (firstInteraction === null) firstInteraction = performance.now() - t0;
    const d = (window.scrollY + window.innerHeight) / Math.max(document.body.scrollHeight, 1);
    scrollMax = Math.max(scrollMax, d); scrollSamples++;
  };
  const onKey = () => { keyCount++; if (firstInteraction === null) firstInteraction = performance.now() - t0; };
  const onTouch = () => { touchCount++; if (firstInteraction === null) firstInteraction = performance.now() - t0; };

  addEventListener('mousemove', onMove, { passive: true });
  addEventListener('scroll', onScroll, { passive: true });
  addEventListener('keydown', onKey, { passive: true });
  addEventListener('touchstart', onTouch, { passive: true });

  // Honeypot — hidden anchor injected on the page; clicks come only from blind crawlers
  document.querySelectorAll('a[data-honeypot]').forEach(a =>
    a.addEventListener('click', () => { honeypotTripped = true; }));

  const flush = () => {
    const payload = {
      sid: (window as any).__sid,                       // session id mirrored from GA4
      ua: navigator.userAgent,
      lang: navigator.language,
      langs: navigator.languages?.length ?? 0,
      plugins: navigator.plugins?.length ?? 0,
      wd: 'webdriver' in navigator ? (navigator as any).webdriver : null,
      dpr: window.devicePixelRatio,
      vp: [innerWidth, innerHeight],
      sc: [screen.width, screen.height],
      hw: (navigator as any).hardwareConcurrency ?? 0,
      mem: (navigator as any).deviceMemory ?? 0,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      perm: 'permissions' in navigator,
      conn: (navigator as any).connection?.effectiveType ?? null,
      ttfi: firstInteraction,
      dur: performance.now() - t0,
      mouseEntropy: mouseSamples ? mouseDeltaSum / mouseSamples : 0,
      mouseSamples, scrollMax, scrollSamples, keyCount, touchCount,
      hp: honeypotTripped,
    };
    navigator.sendBeacon('/api/trust', new Blob([JSON.stringify(payload)], { type: 'application/json' }));
  };

  addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flush(); });
})();
```

**Server-side `/api/trust` route** then writes to your warehouse and feeds the scoring engine in §13.

---

## 11. Cloudflare WAF Rules (paste-ready expressions)

> Tune thresholds against your data. Start in **Log** action, watch 24h, then graduate to **Managed Challenge** → **JS Challenge** → **Block**.

### 11.1 Block obvious automation
```
(cf.bot_management.score lt 5 and not cf.client.bot)
or (http.user_agent contains "HeadlessChrome")
or (http.user_agent contains "Puppeteer")
or (http.user_agent contains "Playwright")
or (http.user_agent contains "phantomjs")
or (http.user_agent contains "Electron")
```
Action: **Block** (Googlebot/Bingbot exempted via `cf.client.bot`).

### 11.2 Challenge Chrome UAs missing client hints
```
http.user_agent contains "Chrome/" 
and http.request.version eq "HTTP/2"
and not any(http.request.headers.names[*] eq "sec-ch-ua")
```
Action: **Managed Challenge**.
**Critical:** exclude `cf.client.bot` so verified Googlebot doesn't hit this.

### 11.3 Block known datacenter/proxy ASNs masquerading as users
Maintain a list (start with these notorious abuse ASNs):
```
ip.geoip.asnum in {
  14061  /* DigitalOcean */
  16509  /* Amazon AWS */
  14618  /* AWS */
  15169  /* Google Cloud — careful, exclude Googlebot via cf.client.bot */
  16276  /* OVH */
  24940  /* Hetzner */
  20473  /* Choopa / Vultr */
  63949  /* Linode / Akamai */
  9009   /* M247 */
  51852  /* Plus Server */
  60068  /* Datacamp */
  202425 /* IP Volume — frequently used by abuse */
  208046 /* HZ Hosting */
  399629 /* BLNWX */
}
and not cf.client.bot
and http.request.uri.path matches "^/(?!api/|_next/|sitemap)"
```
Action: **Managed Challenge** (not block — some legit users behind VPNs).

### 11.4 Challenge residential-proxy ASNs (use sparingly — high false-positive risk)
Only after data confirms abuse from these:
```
ip.geoip.asnum in { /* known proxy providers */ ... }
and cf.bot_management.score lt 30
```
Action: **JS Challenge**.

### 11.5 Rate limiting (Cloudflare Rate Limiting Rules)
- **Per-IP:** 100 requests / minute / IP on `/article/*` → JS Challenge
- **Per-ASN:** 5000 requests / minute / ASN (excluding `cf.client.bot`) → Managed Challenge
- **Per-JA3:** 10000 requests / minute / JA3 hash → Block (an ASN-spanning JA3 collapse is a strong bot signal)

### 11.6 Honeypot path
```
http.request.uri.path eq "/bot-trap"
```
Action: **Block** + add IP to dynamic abuse list for 24h.

### 11.7 SEO-safe carve-out (always-on)
```
cf.client.bot
or http.user_agent matches "Googlebot|Bingbot|Applebot|DuckDuckBot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|TelegramBot|WhatsApp"
```
This expression should appear with **Skip** action **above** every challenging rule. Validates UA, then Cloudflare's reverse-DNS verification (`cf.client.bot`) provides the cryptographic part. The two combined are the standard for not breaking SEO.

---

## 12. SEO-Safe Design Principles (so we don't blow up Discover)

1. **Never challenge `cf.client.bot`** — Cloudflare verifies Googlebot/Bingbot via reverse DNS; this field is trustworthy.
2. **Allow `GPTBot`, `ClaudeBot`, `PerplexityBot`, `Applebot-Extended`** only if you want LLMs to train on your content. If you don't, list them in `/robots.txt` rather than blocking at WAF — blocking at WAF without `robots.txt` declaration looks erratic.
3. **Never use a JS challenge on `/sitemap.xml`, `/robots.txt`, `/feed`** — these must be reachable to bots.
4. **CWV preservation** — the fingerprint beacon must:
   - Be inline (no extra request)
   - Be `<2KB` minified
   - Use `passive: true` listeners
   - Not block paint
   - Fire `sendBeacon` only on `visibilitychange` (no extra network during render)
5. **Verify CWV after rollout** with `web-vitals` library, compare 7-day p75 INP/LCP before/after deployment of any challenge.

---

## 13. Behavioral Scoring Engine — Architecture

A trust score in `[0, 100]` per session, computed server-side from edge + client beacon signals.

```
trust_score = clamp(0, 100,
    50
  + 30 * cf_bot_score_normalized            // 0–1 from CF
  - 25 * I(ja3_in_top_collapsed_set)
  - 20 * I(asn_in_datacenter_list)
  - 15 * I(asn_in_proxy_list)
  - 30 * I(ua_chrome_missing_ch_ua)
  - 25 * I(navigator_webdriver_true)
  - 20 * I(plugins_zero_and_languages_one)
  + 15 * I(ttfi_present and ttfi < 60_000)
  + 10 * I(mouse_entropy > threshold)
  + 10 * I(scroll_max > 0.25)
  +  5 * I(persistent_cookie_returning_user)
  - 40 * I(honeypot_tripped)
  - 15 * I(engagement_time_in_900_1100_ms_band)
)
```

**Bands:**
- `>= 70` → trusted (full experience, ad render, GA4 included)
- `40–69` → soft-suspicious (render content, hold ad bids, exclude from GA4 aggregates via a server-side filter)
- `20–39` → JS challenge on next nav
- `< 20` → shadow-block (serve cached HTML only, no DB writes, no ad calls)

Persist score in an edge KV (Cloudflare KV / Vercel KV) keyed by `(ja3, asn, ua_hash)` so repeat offenders accumulate evidence.

### V2: ML anomaly detection
- Feature vector: 25–40 features above + `request_rate_per_minute`, `path_diversity`, `referer_distribution`
- Model: **Isolation Forest** for unsupervised anomaly score on session-level features (no labels needed), retrained nightly on last 14 days
- Add **HDBSCAN** clustering on JA3 + UA + path signatures to surface botnet "campaigns" — operators often deploy a fleet that clusters tightly

---

## 14. Honeypot & Trap Designs

| Trap | What | Catches |
|---|---|---|
| **Hidden anchor** | `<a href="/bot-trap" data-honeypot style="position:absolute;left:-9999px" aria-hidden="true" tabindex="-1">x</a>`, disallowed in `robots.txt` | Blind link-following scrapers |
| **JS-only link** | Link rendered only after a real user gesture (`pointermove` listener attaches it) | Pre-render scrapers |
| **Canary article** | Slug never linked from site; only listed in sitemap with `noindex` meta — anyone visiting it is reading sitemap mechanically | Sitemap-driven scrapers |
| **Mouse-required CTA** | Buttons that require a `pointerdown` event sequence (no `click` synthesis) to function | Headless click simulation |
| **Form trap** | Hidden form field "website" — if filled, it's a bot | Generic spam bots |
| **Time-based gate** | "Read more" reveal that requires >2s page-time before mounting | Sub-second scrapers |

Honeypot trips should be **silent** — never tell the bot it's been caught, or operators adapt.

---

## 15. Monitoring Dashboard (fits naturally into your existing command-center)

The existing widgets (`PipelineWidget`, `EditorialWidget`, `TrendingWidget`) suggest a Grafana-style operator console. Add:

1. **Bot Score Distribution** — histogram of Cloudflare BotScore, last 24h, segmented by trusted/suspicious/blocked
2. **Engagement Histogram** — overlay of GA4 `engagement_time_msec` against the rolling 30-day "trusted" baseline (Earth Mover's Distance > 0.2 → alert)
3. **ASN Watchlist** — top 20 ASNs by request volume, sortable by `req_per_ip` and `avg_bot_score`; red row if `req_per_ip < 3` and volume > 10k/h
4. **JA3 Collapse Detector** — top 10 JA3 hashes by `unique_ips × unique_asns` product; alert when any single JA3 spans >500 IPs
5. **GA4 vs. Search Console** — daily session-to-impression ratio by landing page; outlier detection (z-score > 3)
6. **Ad-Side Health** — RPM, viewability, IVT rate per SSP, with 7-day rolling trend
7. **Honeypot Trips** — live feed of IPs/ASNs caught, with auto-block status
8. **Trust-Score Funnel** — sessions by trust band, conversion (real engagement) by band, validating that the score correlates with behavior

Alert thresholds (PagerDuty/Slack):
- Bot share of pageviews > 40% (1h window)
- Engagement histogram EMD vs baseline > 0.2
- New JA3 collapse cluster (>1000 IPs)
- Single-ASN spike > 5σ above rolling mean

---

## 16. Server-Side Event Validation

Move conversions and analytics where it matters (newsletter signup, content reads measured for editorial decisions, ad attribution) to **server-side GTM** with a shared HMAC token between page and server:

1. Page receives short-lived signed token in HTML (signed by Vercel edge middleware with a daily-rotating key)
2. Beacons to `/api/event` include token + payload
3. Server verifies signature, then rejects events from sessions whose trust score is < 40 or whose token signature fails
4. Forward filtered events to GA4 via Measurement Protocol with `validation_code` set

This makes it materially harder to replay or fabricate analytics events — a common tactic in engagement-poisoning attacks.

---

## 17. Crawl Budget & Real Bot Protection

- **Allowlist verified bots at the edge with a fast-path** — `cf.client.bot` rule comes first in evaluation order
- **Set `Cache-Control: public, s-maxage=300, stale-while-revalidate=86400`** on article HTML so Googlebot hits Cloudflare edge, not Next.js origin — protects crawl-rate budget
- **Sitemap segmentation** — split sitemap by section; if scrapers hammer one section, you can rate-limit the sitemap subset without affecting indexing of others
- **Googlebot rate observability** — log Googlebot's request rate separately; if it drops sharply, that's a "Google reduced crawl due to perceived server issues" signal

---

## 18. Most Likely Verdict (best guess pending data)

Given the symptoms — sub-1s engagement, distributed IPs, JS-executing, no interaction — and that FandomWire is a celebrity/fandom publication (high scrape value, high competition for Discover slots), the leading explanation is a combination:

1. **~40–60% of the anomalous traffic** is **headless-browser scrapers** harvesting articles for content aggregation, LLM training, or rival sites. These will be **DC-ASN heavy** with **JA3 collapse** and **missing client hints**.
2. **~20–30%** is **residential-proxy traffic** running engagement-style fraud — either competitor sabotage, a "boost" service the team isn't aware of, or ad-fraud arbitrage. These will look like real ISPs but cluster on a small set of behavioral and TLS fingerprints.
3. **~10–20%** is **AI crawlers** (some declared, some spoofed) — relatively benign but inflating numbers.
4. **Residual** is real low-quality referral traffic (Facebook/Outbrain), which is normal.

**Confidence in this composite: 0.7**, will rise to **>0.95** once Cloudflare BotScore + JA3 + GA4 histogram data is in.

---

## 19. Implementation Roadmap (next 30 days)

| Week | Deliverable | Owner |
|---|---|---|
| 1 | Logpush + GA4 BigQuery export + fingerprint beacon shipped | Eng + Data |
| 1 | §6 queries run, §7 anomaly report filled, verdict confirmed | Data + Security |
| 2 | Cloudflare WAF rules (§11) deployed in Log mode, then promoted | Security |
| 2 | Ad-render gating (no GPT until interaction signal) | Ad Eng |
| 3 | Trust-score engine v1, server-side event validation | Eng |
| 3 | Honeypots deployed | Eng |
| 4 | Monitoring dashboard widgets added to command-center | Eng |
| 4 | First retrospective: measure RPM delta, SEO delta, CWV delta | Leadership |

---

## 20. What NOT to Do

- **Don't block by user agent string alone.** Trivially spoofed; high false-positive risk.
- **Don't deploy aggressive blocks before data review.** You will tank real users in low-bandwidth markets (Africa, SE Asia) who do legitimately bounce fast on mobile.
- **Don't block AI crawlers at the WAF without first declaring them in robots.txt.** Some respect robots; if they don't, then WAF — but lead with the standard.
- **Don't add hCaptcha/reCAPTCHA site-wide.** Catastrophic for CWV and reader experience. Use only for `BotScore < 20` and only on non-article paths.
- **Don't trust GA4 numbers without server-side cross-checks.** They are precisely what the attacker is poisoning.
- **Don't fight the wrong attacker.** Confirm the type before designing defenses — overfitting to one operator leaves you exposed to the next.

---

*End of report. Section §3, §6, and §7 are the critical path: until those data sources are wired up and queries run, every defense recommendation is provisional. Once the data is in, this document should be re-anchored on facts, not priors.*
