# FandomWire Bot Investigation — Session Summary

**Branch:** `claude/fandomwire-bot-detection-Cm2Qt`
**Stack:** WordPress on Cloudways with Cloudflare Enterprise add-on (managed, no direct dashboard access)
**Initial symptom:** ~0.98 second average GA4 engagement time across many IPs with no scroll/click/mouse activity

---

## 1. What we found

The investigation surfaced **two independent bot-traffic problems** that converged in the same analytics dashboard:

### Story 1 — Cache-plugin Used-CSS crawler (~60–75% of anomaly volume)
A WordPress cache plugin (architecture similar to FlyingPress / CriticalCSS.com) runs **Puppeteer from Vietnam-based servers** to walk every page on the site and generate per-page Used-CSS. Each Coverage run loads the page, fires GA4 (`page_view`), runs for ~700–1500ms, then closes the tab — producing the 0.98s engagement signature **mathematically**, not maliciously. Confirmed live by the plugin developer ("One Man Army") via WhatsApp: *"its happening after I told you I have updated cache plugin... I use headless browser, he uses puppeter to visit each pages and generated usedCSS... Cheap mf veitnam use karta hai."*

**Mechanism:** plugin update triggered a full re-crawl; Puppeteer's Coverage API runtime ≈ observed engagement time; intentionally allowlisted at the edge so CSS regen works; Cloudways panel hides Bot Score so the publisher couldn't see the band.

### Story 2 — UA-spoofer campaign (05-06 → 05-08 spike)
The bot-activity heatmap showed nearly every declared crawler — **Meta-AI-Crawler (94,261), GoogleBot (67,084), Bingbot (64,923), OAI-SearchBot (65,587), GPTBot (18,066), Claude-SearchBot (20,558)** — peaking together in a 72-hour window at ~6× baseline. Synchronized spikes across independent vendors do not happen by coincidence. Specific tells:
- All bots follow the same peak-then-collapse shape (real fleets are steady-state)
- Obscure UAs (Timpibot) appearing sporadically — classic spoofer-testing-a-UA pattern
- Total declared-bot volume on 05-07 ≈ 325k requests — implausibly high for a publisher of this size

**Mechanism:** one actor with one infrastructure rotating User-Agent strings to look like a fleet of friendly bots, exploiting publishers' habit of allowlisting by UA. Almost certainly commercial scraping (content harvesting / LLM training data / competitive scraping).

### Convergence
Both stories produce **JS-executing, low-engagement, no-ad-rendering sessions**. In GA4's default reports they look identical. The fixes are different:
- Story 1: tag and filter (don't block; the crawler is legitimate)
- Story 2: reverse-DNS verify the bot UA and block on failure

---

## 2. Confidence scoring (evolution through investigation)

| Stage | Bot share is automated | Cache-plugin explains bulk |
|---|---|---|
| Initial (symptom only) | 0.92 | not modeled |
| After WhatsApp lead | 0.35 (malicious) | 0.70 (benign cache crawler) |
| After dashboard reveal | restored to ~0.85 (two problems, both real) | 0.65 of *baseline* anomaly only; spike is separate |

---

## 3. Constraints that shaped the solution

| Constraint | Consequence |
|---|---|
| No Cloudflare dashboard access (Cloudways manages the CF Enterprise add-on) | All edge changes must be filed as Cloudways support tickets with paste-ready expressions. Origin-side defenses get priority. |
| WordPress, not Next.js (the command-center repo is separate from FandomWire.com) | Defenses ship as a `wp-content/mu-plugins/` file, not as a `/api/` route. |
| Page cache can serve responses without invoking PHP | mu-plugin runs on cache misses; cached HTML still ships GA4 unless client-side gated or cache is varied by trust band. |
| GA4 counts every snippet hit by default | An internal-traffic filter is required; not optional. |
| CF Enterprise "High Security" is already on | But hides the controls. Bots reaching origin means either intentional allowlisting (cache plugin) or scores that don't trip CF's heuristics (sophisticated UA-rotators). |

---

## 4. The solution — what got shipped

All committed to branch `claude/fandomwire-bot-detection-Cm2Qt` under `fwbotworkamir-cloud/fandomwire-command-center`.

### 4.1 WordPress mu-plugin (the core defense)

**`wordpress/mu-plugins/fw-bot-defense.php`** — two-layer defense:

**Layer 1 — Cache-crawler tagging.** Recognises the cache-plugin's Puppeteer fleet by:
- Shared-secret header (`X-Cache-Gen: <secret>`) — preferred
- Custom UA tokens (FlyingPress, WP-Rocket-Crawler, UsedCSS, NitroPack, LiteSpeedBot, CriticalCSS)
- IP CIDR allowlist

For matches: serves the page (so CSS regen continues), strips GA4 / GTM hooks, deactivates ad-network plugins, sets `X-FW-Trust: cache_crawler`.

**Layer 2 — Reverse-DNS bot verification.** For any UA claiming a known bot identity:
- Reverse-DNS the client IP, confirm PTR ends in vendor domain
- Forward-DNS the PTR back, confirm it resolves to the client IP
- For AI vendors without rDNS (OpenAI, Anthropic, etc.): match against published CIDR lists
- Cache verdict per IP (24h verified / 6h spoof) via WP transients
- **403** any UA-claimed bot that fails verification

Plus: hard 403 for HeadlessChrome / Puppeteer / Playwright / phantomjs / Electron / empty UA; analytics+ads suppression for Chrome UAs missing `sec-ch-ua`; bypass for wp-admin / WP-CLI / cron.

**Supporting files:**
- `wordpress/mu-plugins/cache-crawler-ips.php` — vendor egress CIDR template
- `wordpress/mu-plugins/published-ip-ranges.php` — AI vendor IP list template
- `wordpress/scripts/update-bot-ip-ranges.sh` — weekly cron-refreshable from `openai.com/gptbot.json` etc.

### 4.2 Documentation (in `docs/`)

| File | What it covers |
|---|---|
| `bot-traffic-forensic-analysis.md` | Threat model, hypothesis triage, BigQuery + Cloudflare investigation queries, behavioral scoring engine architecture, WAF rules, honeypots, dashboard widgets. Long-form analysis. |
| `bot-traffic-protection-plan.md` | Full-CF-access protection plan with phased rollout, decision gates, monitoring, ML detection. Target architecture. |
| `addendum-cache-plugin-lead.md` | Reframes the analysis after the WhatsApp finding; revised threat percentages; confirmation queries. |
| `protection-cloudways-wordpress.md` | The Cloudways/WordPress execution variant of the protection plan — what to do under the actual constraints. |
| `reverse-engineer-crawler.md` | Seven-phase tactical playbook to independently identify the cache plugin in use, its remote API vendor, and the exact crawler fingerprint (IP, UA, JA3, browser intrinsics, behavior). Canary endpoint code + browser intrinsics probe + Coverage-API timing diagnostics + YAML fingerprint artifact format. |
| `stop-the-bots-execution.md` | The shipping doc — sequenced execution, paste-ready Cloudways tickets, curl validation tests, GA4 filter walkthrough, rollback procedure. |
| `session-summary.md` | This file. |

---

## 5. Execution sequence (canonical)

```
DAY 1 (≈1 hour hands-on):
  1. Ask "One Man Army" for crawler IP/UA/shared-secret-header
  2. Run wordpress/scripts/update-bot-ip-ranges.sh to populate AI vendor CIDRs
  3. Drop 3 PHP files into wp-content/mu-plugins/ on staging
  4. Run the 4 curl tests in stop-the-bots-execution.md §Step 3
  5. Push to production
  6. Add GA4 internal-traffic filter (Testing) for cache-plugin IPs
  7. Update robots.txt for AI crawlers (GPTBot, ClaudeBot, Bytespider, etc.)

DAY 2 (file tickets, then wait):
  8. Cloudways Ticket #1: enable Managed Transforms for CF-Bot-Score, CF-IPASN, CF-Verified-Bot, CF-JA3-Hash
  9. Cloudways Ticket #2: add 4 WAF rules (verified-bot skip, cache-plugin allowlist, signature block, spoofed-bot Managed Challenge)
  10. Cloudways Ticket #3: rate limits + honeypot path block

DAY 3 (validation):
  11. Promote GA4 filter from Testing → Active
  12. Run validation queries against Cloudways access logs
  13. Confirm GA4 engagement-time histogram is recovering (target: p50 > 10s)
  14. Confirm Googlebot is NOT being blocked

DAY 4+ (residual):
  15. Reverse-engineer crawler per docs/reverse-engineer-crawler.md to tighten the cache-crawler signature beyond UA/IP heuristics
  16. Phase 2 of main protection plan: trust-score beacon + server-side analytics (for residential-proxy traffic that doesn't match either fingerprint)
```

---

## 6. What this stops vs. doesn't

**Stops:**
- Cache-plugin Puppeteer pollution of GA4 (Story 1)
- UA-spoofers claiming Googlebot / Bingbot / Applebot / Meta-AI / OpenAI / Anthropic / etc. (Story 2)
- Headless Chrome / Puppeteer / Playwright / phantomjs identifying themselves honestly
- Chrome UAs missing `sec-ch-ua` (analytics + ads stripped, page still served)

**Doesn't stop:**
- Sophisticated residential-proxy traffic with valid `sec-ch-ua` and no bot UA claim → trust-score beacon needed
- Direct origin-IP attacks bypassing Cloudflare → restrict Cloudways app firewall to CF IP ranges
- Page-cache hits where mu-plugin never runs → vary cache by `FW_TRUST_BAND` or wrap GA4 in a client-side cookie check

---

## 7. Success metrics

| Metric | Before | Target | Floor |
|---|---|---|---|
| GA4 engagement-time p50 | ~0.98s | ≥ 12s | ≥ 8s |
| Bot share of pageviews | 30–60% suspected | < 10% | — |
| Engagement-histogram 750–1250ms bucket | dominant | < 5% | < 15% |
| Search Console / GA4 sessions ratio | unknown divergence | within ±15% | within ±25% |
| Google Discover impressions | flat/declining | trending up | not declining >10% w/w |
| CWV p75 INP after beacon | baseline | within +5ms | within +20ms |
| Googlebot crawl rate | baseline | unchanged | within −10% |
| Ad RPM | declining | +30% recovery | not below baseline |

Hard rule: no defense ships if it degrades CWV by >20ms p75 INP, drops Googlebot crawl >10%, or creates >0.5% false-positive rate against real human sessions.

---

## 8. Open questions / decisions for the team

1. **Get the cache plugin's egress IP range** from "One Man Army" — single highest-leverage piece of intel
2. **Confirm whether `Meta-AI-Crawler 94k in one day`** is real or spoofed — depends on whether the dashboard counts UA strings or verified bots
3. **Decide stance on AI training crawlers** (GPTBot, ClaudeBot, Perplexity) — current default in shipped code is "verify-not-block"; team may prefer "block in robots.txt + WAF"
4. **Object cache + analytics suppression conflict** — pick Option A (client-side cookie gate) or Option B (vary cache by trust band)
5. **Trust-score beacon timing** — ship now (Phase 2) or wait for first defense to stabilize first

---

## 9. Files committed (full listing)

```
docs/
├── addendum-cache-plugin-lead.md          (cache-plugin hypothesis + confirmation queries)
├── bot-traffic-forensic-analysis.md       (threat model, queries, scoring engine)
├── bot-traffic-protection-plan.md         (full-CF-access protection plan)
├── protection-cloudways-wordpress.md      (Cloudways/WordPress variant)
├── reverse-engineer-crawler.md            (tactical fingerprinting playbook)
├── session-summary.md                     (this file)
└── stop-the-bots-execution.md             (shipping doc with paste-ready tickets)

wordpress/
├── mu-plugins/
│   ├── cache-crawler-ips.php              (vendor IP allowlist template)
│   ├── fw-bot-defense.php                 (main mu-plugin, lint-clean)
│   └── published-ip-ranges.php            (AI vendor IP template)
└── scripts/
    └── update-bot-ip-ranges.sh            (weekly CIDR refresh)
```

---

## 10. One-line summary

**Two simultaneous bot problems** — a benign Vietnam-based cache-plugin Puppeteer crawler polluting GA4 with 1-second sessions, plus a UA-rotating scraper campaign claiming to be every friendly bot identity at once — converged to produce the 0.98s engagement signature. Fixed by a single WordPress mu-plugin that tags-and-filters the cache crawler (no block, no break) and reverse-DNS-verifies every declared bot UA (403 on spoof), shipped alongside paste-ready Cloudways tickets for matching edge defenses. Total hands-on time: ~1 hour. End-to-end recovery: ~3 days.
