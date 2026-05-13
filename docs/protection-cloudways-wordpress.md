# FandomWire — Protection Playbook for Cloudways + Cloudflare Enterprise Add-on (WordPress)

**Constraint:** No direct Cloudflare dashboard access. Site runs on **Cloudways** with the **Cloudflare Enterprise add-on**, **High Security** plan setting enabled. Stack is **WordPress**.

**Implication:** Most actions in the main protection plan are not directly shippable. They become either (a) requests to Cloudways support, who have CF API access, or (b) origin-level (WordPress/server) defenses that bypass the CF restriction entirely.

This document supersedes the main protection plan for **execution sequencing** under these constraints. The main plan still defines the *target architecture*.

---

## 1. What you already have for free

Cloudways' CF Enterprise add-on with **High Security** is **not nothing**. By default this gives you:

| Cloudflare Enterprise feature | On by default? | Acting on your traffic right now? |
|---|---|---|
| Bot Management ML (`BotScore`) | Yes, runs on every request | Yes — but you can't see the score |
| Managed WAF Rules (Cloudflare-managed) | Yes | Yes |
| Security Level: High | Per your setting | Challenges visitors with bad IP reputation in the last 14 days |
| Verified-bot allowlist | Yes | Googlebot, Bingbot, etc. pass through correctly |
| TLS termination + JA3/JA4 inspection | Yes | Logged but not exposed to you |
| DDoS protection (L3/L4/L7) | Yes | Yes |
| HTTP/3, Brotli, Argo Smart Routing | Often included | Yes |

**This means:** if blatantly bot-fingerprinted traffic (HeadlessChrome UA, low BotScore, known proxies) is still reaching the origin and showing up in GA4, **one of three things is true**:
1. The bots are sophisticated enough to score above CF's challenge threshold (residential proxies + stealth plugins routinely do).
2. **The cache-plugin crawler is being intentionally allowlisted** somewhere — most cache plugins do this via a Cloudways IP allowlist, an `X-Forwarded-For` trust header, or a User-Agent suffix that Cloudways pre-allows.
3. High Security is not actually applying to the origin's domain (sometimes Cloudways setups have a misconfigured proxy chain).

**Hypothesis prior, given the WhatsApp lead:** option 2 is dominant. The cache-plugin's Puppeteer fleet is allowlisted by design.

---

## 2. The play, in two tracks

Track A — what we can do **without** any Cloudways support involvement (ship today)
Track B — what we need Cloudways support to do for us (file ticket Monday)

Both tracks run in parallel.

---

## 3. Track A — Origin & client-side (no CF access needed)

### 3.1 GA4 internal-traffic filter — biggest single win, 15 minutes of work
**This is the action that fixes the 0.98s engagement number on day 1.** Doesn't require Cloudflare, doesn't require Cloudways, doesn't require anyone's permission except GA4 admin.

1. Confirm the cache-plugin's egress IP range with "One Man Army" (or read it off the plugin's docs / a few hours of Cloudways access logs — see §3.3).
2. GA4 → **Admin** → **Data Streams** → select the web stream → **Configure tag settings** → **Show all** → **Define internal traffic**
3. Add a rule:
   - Rule name: `cache-plugin-crawler`
   - Traffic type value: `internal`
   - IP matching: `IP address in CIDR range` (or in range, or equals) — paste the cache-plugin IPs
4. GA4 → **Admin** → **Data Settings** → **Data Filters** → **Create filter**
   - Filter type: **Internal traffic**
   - Filter state: start at **Testing** for 48h, then promote to **Active**
   - This will mark events from those IPs with `traffic_type=internal` and exclude them from standard reports.

Within 24h of activation the engagement-time metric will reflect humans only.

**Important:** also add a filter for known datacenter ranges if you can identify them. GA4 does not auto-exclude bot traffic from BQ export — you have to filter on query.

### 3.2 WordPress mu-plugin — server-side fingerprint + tag
Drop this in `wp-content/mu-plugins/fw-trust.php`. It runs before any plugin, captures request fingerprint to a log file (or, ideally, a small DB table), and **prevents GA4 / ad / heavy plugin code from loading for bot-tagged requests**.

```php
<?php
/*
Plugin Name: FW Trust (must-use)
Description: Server-side bot tagging + heavy-asset gating
*/
if (!defined('ABSPATH')) exit;

add_action('muplugins_loaded', function () {
    $req = $_SERVER;
    $ua  = $req['HTTP_USER_AGENT']   ?? '';
    $ip  = $req['HTTP_CF_CONNECTING_IP'] ?? ($req['REMOTE_ADDR'] ?? '');
    $asn = (int)($req['HTTP_CF_IPASN']  ?? 0);                       // request from CW support
    $bs  = (int)($req['HTTP_CF_BOT_SCORE'] ?? 100);                  // request from CW support
    $vb  = !empty($req['HTTP_CF_VERIFIED_BOT']);                     // request from CW support
    $secchua = $req['HTTP_SEC_CH_UA'] ?? null;

    // --- 1. Trusted bots: leave alone (do NOT break SEO) ---
    if ($vb || preg_match('~Googlebot|Bingbot|Applebot|DuckDuckBot|Twitterbot|facebookexternalhit|LinkedInBot~i', $ua)) {
        define('FW_TRUST_BAND', 'verified_bot');
        return;
    }

    // --- 2. Cache-plugin crawler signature (allowlist tag, suppress analytics) ---
    $cache_crawler_uas   = ['FlyingPress', 'WP-Rocket-Crawler', 'UsedCSS', 'NitroPack', 'LiteSpeedBot'];
    $cache_crawler_ips   = include __DIR__ . '/cache-crawler-ips.php';     // array of CIDRs from plugin author
    $is_crawler_ua = false;
    foreach ($cache_crawler_uas as $token) if (stripos($ua, $token) !== false) { $is_crawler_ua = true; break; }
    if ($is_crawler_ua || fw_ip_in_cidrs($ip, $cache_crawler_ips)) {
        define('FW_TRUST_BAND', 'cache_crawler');
        // strip analytics + ads for this request
        add_action('init', function () {
            remove_action('wp_head', 'gtag_head');       // adjust to your actual analytics hook
            remove_action('wp_footer', 'gtag_footer');
            add_filter('option_active_plugins', 'fw_strip_ad_plugins');
        }, 1);
        return;
    }

    // --- 3. Cheap signature blocks (rare; CF Enterprise should catch these, but defense-in-depth) ---
    if (stripos($ua, 'HeadlessChrome') !== false
        || stripos($ua, 'Puppeteer') !== false
        || stripos($ua, 'Playwright') !== false
        || stripos($ua, 'phantomjs') !== false
        || $ua === '') {
        status_header(403);
        header('Cache-Control: no-store');
        exit;
    }

    // --- 4. sec-ch-ua consistency (high-precision bot signal) ---
    $claims_chrome = stripos($ua, 'Chrome/') !== false;
    $is_https      = !empty($req['HTTPS']) || ($req['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    if ($claims_chrome && $is_https && $secchua === null) {
        define('FW_TRUST_BAND', 'ua_mismatch');
        // serve content (don't 403 — risk of FP), but suppress GA + ads
        add_action('init', 'fw_strip_analytics_and_ads', 1);
        return;
    }

    // --- 5. Otherwise: trusted by default ---
    define('FW_TRUST_BAND', 'trusted');
});

function fw_ip_in_cidrs($ip, $cidrs) {
    foreach ($cidrs as $cidr) {
        [$subnet, $bits] = strpos($cidr, '/') !== false ? explode('/', $cidr) : [$cidr, 32];
        if ((ip2long($ip) & (~((1 << (32 - (int)$bits)) - 1))) === (ip2long($subnet) & (~((1 << (32 - (int)$bits)) - 1)))) return true;
    }
    return false;
}
function fw_strip_analytics_and_ads() {
    // remove your specific GA4/GTM action hooks here
    remove_action('wp_head', 'gtag_head');
    remove_action('wp_footer', 'gtag_footer');
}
function fw_strip_ad_plugins($plugins) {
    $strip = ['ad-inserter/ad-inserter.php', 'advanced-ads/advanced-ads.php'];
    return array_values(array_diff($plugins, $strip));
}
```

Effect:
- **Cache crawler hits no longer fire GA4 → engagement-time metric cleans up.**
- Cache crawler hits no longer call ad networks → ad inventory quality recovers.
- Cheap signature bots (HeadlessChrome, etc.) get 403 before WordPress boots → server load drops.
- `sec-ch-ua` mismatches get content but no analytics/ads → safe halfway response.
- `FW_TRUST_BAND` is now defined and can be read by other plugins or the cache plugin itself.

**Why a mu-plugin and not a regular plugin:** mu-plugins load before regular plugins, so they can suppress analytics/ad plugins' `wp_head` actions before they fire. A regular plugin loads too late.

**Important:** the headers `CF-Connecting-IP`, `CF-Bot-Score`, `CF-IPASN`, `CF-Verified-Bot` only arrive if Cloudways/Cloudflare is configured to forward them. `CF-Connecting-IP` typically does (Cloudways uses it for real IPs). `CF-Bot-Score`, `CF-IPASN`, `CF-Verified-Bot` are **Cloudflare Enterprise transforms** that have to be enabled — this is one of the items in the Cloudways support ticket below (§4.1).

### 3.3 Cloudways access-log analysis (your Logpush substitute)
On Cloudways, every app has Apache access logs at:
```
/home/master/applications/<app-name>/logs/apache_<app-name>.access.log
```
Accessible via Cloudways SSH (Application → Master Credentials → SSH).

**This gives you the data Logpush would have.** Not as rich (no BotScore, no JA3), but enough to confirm the cache-plugin hypothesis and find heavy hitters.

Quick triage queries:

```bash
# Top IPs by request volume last 24h
awk '$4 > "['"$(date -d '24 hours ago' '+%d/%b/%Y:%H:%M:%S')"'"' apache_<app>.access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -50

# Top User-Agents
awk -F'"' '{print $6}' apache_<app>.access.log | sort | uniq -c | sort -rn | head -30

# Path coverage by IP (the cache-crawler signature)
awk '{print $1, $7}' apache_<app>.access.log | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head -30
# IPs hitting hundreds of distinct paths in a short window → cache crawler

# Look for Puppeteer-y UAs
grep -iE 'headlesschrome|puppeteer|playwright|phantomjs|crawler|usedcss|flyingpress' apache_<app>.access.log | head -50

# Cache plugin signature search
grep -i 'cache-warmer\|criticalcss\|prefetch' apache_<app>.access.log | awk '{print $1}' | sort -u | head -50
```

For ongoing analysis, set up daily rotation → S3 or BigQuery via `aws s3 cp` cron or `bq load`. Cloudways doesn't natively ship logs anywhere, so you build it yourself.

### 3.4 Coordinate with the cache-plugin developer ("One Man Army")
Request directly:
1. **Exact egress IP range / CIDR.** Save to `wp-content/mu-plugins/cache-crawler-ips.php` as a PHP array.
2. **Custom UA token** the crawler sends — confirm it matches what's in the mu-plugin signature list.
3. **Optional but ideal:** make the crawler send a shared-secret header (`X-Cache-Gen: <secret>`) so identification is cryptographic, not heuristic.
4. **Crawl scheduling:** can the crawl run at low-traffic hours (3–5am site-local) so even unfiltered analytics looks less alarming during reader-active windows?
5. **Per-page concurrency cap:** find out what concurrency the crawler uses; if it's hammering the origin too hard, ask for a lower cap.

These five asks resolve the bulk of the symptom for free.

### 3.5 Client-side beacon (still useful)
The beacon from the main protection plan still ships — but **on the WordPress side**, not in this Next.js command-center repo.

Implementation path:
- Create a tiny plugin `fw-trust-beacon` that:
  - Enqueues the JS inline in `wp_footer` (≤ 2KB minified)
  - Registers a REST route `wp-json/fw/v1/trust` for the beacon to POST to
  - Writes to a `wp_fw_trust` table (small, indexed by session_hash)
- The beacon code itself is the one from analysis §10
- The REST handler computes the trust score from §13 of the analysis doc

**Where the trust score gets used:**
- WordPress can read it on the *next* pageview (cookie-set) and pass it to your ad-rendering plugin to gate Prebid/GPT
- Or you can expose it as a custom GA4 dimension via `gtag('config', GA_ID, {'trust_band': trust_band})` to let GA4 segment on it

### 3.6 robots.txt hardening
Pure WordPress, ship in 5 minutes. Add to your robots.txt (via Yoast/RankMath custom robots editor or `wp-content/themes/<theme>/robots.txt`):

```
User-agent: GPTBot
Disallow: /                 # if you don't want OpenAI training

User-agent: ClaudeBot
Disallow: /                 # if you don't want Anthropic training

User-agent: PerplexityBot
Disallow: /                 # tends to ignore but worth declaring

User-agent: anthropic-ai
Disallow: /

User-agent: cohere-ai
Disallow: /

User-agent: CCBot
Disallow: /                 # Common Crawl

User-agent: Bytespider
Disallow: /                 # ByteDance / TikTok scraper, aggressive

User-agent: ImagesiftBot
Disallow: /

User-agent: Omgilibot
Disallow: /

User-agent: <your-cache-plugin-crawler-UA>
# (no Disallow — explicitly allowed, but documented)

Sitemap: https://fandomwire.com/sitemap.xml
```

This **doesn't** stop bots that ignore robots.txt (most malicious ones do), but it:
- Removes legal/PR exposure for AI training
- Gives clear evidence in WAF rules that you officially disallow them
- Is required before escalating to WAF blocks (don't WAF-block what you haven't robots-disallowed first)

### 3.7 WordPress plugin: Wordfence / Solid Security / Shield Pro
**Skip unless you have measured value.** These plugins overlap heavily with CF Enterprise and are mostly redundant when CF is in front. The mu-plugin in §3.2 covers the residual gap with surgical precision and zero plugin overhead. Wordfence's live traffic feature is useful for one-off investigation but expensive in CPU at scale.

---

## 4. Track B — Cloudways support tickets

You have CF Enterprise. Cloudways support has the keys. **Frame every request as a single ticket per change, with the exact CF rule expression ready to paste.** Cloudways tickets resolve in 4–24h typically.

### 4.1 Ticket #1 — Enable CF Transform Rules to forward Bot Score + ASN
**Subject:** Please enable CF Transform Rules to forward Bot Score, ASN, and Verified Bot headers to origin
**Body:**
> We need to apply server-side logic based on Cloudflare's bot signals. Please add these **Managed Transforms** or **Transform Rules** on the zone fandomwire.com to add HTTP request headers forwarded to the origin:
>
> - `CF-Bot-Score`: `cf.bot_management.score`
> - `CF-Verified-Bot`: `cf.client.bot`
> - `CF-IPASN`: `ip.geoip.asnum`
> - `CF-Threat-Score`: `cf.threat_score`
> - `CF-JA3-Hash`: `cf.bot_management.ja3_hash` (Enterprise Bot Management)
>
> These are standard fields on the Enterprise plan. We don't need any rule action — just the transform that adds them as request headers reaching our origin.

**Why first:** with these headers, the mu-plugin in §3.2 becomes 10× more accurate — no more guessing UA strings; just read the score.

### 4.2 Ticket #2 — Enable Logpush to our destination
**Subject:** Enable Cloudflare Logpush to S3 / GCS for forensic analysis
**Body:**
> Please configure Cloudflare Logpush on fandomwire.com to push HTTP request logs to our destination:
>
> - Destination: `s3://<our-bucket>/cf-logs/` (or GCS bucket)
> - Frequency: high
> - Fields to include: EdgeStartTimestamp, ClientIP, ClientASN, ClientCountry, ClientRequestUserAgent, ClientRequestPath, ClientRequestReferer, ClientRequestHost, ClientSSLProtocol, ClientSSLCipher, ClientTCPRTTMs, BotScore, BotScoreSrc, JA3Hash, JA4, EdgeResponseStatus, WAFAttackScore, RequestHeaders
> - Sampling: 100% for first 30 days
>
> We've created the destination and IAM access; details attached.

Cloudways occasionally pushes back on Logpush. If they refuse, ask for **CSV log exports** weekly as a workaround.

### 4.3 Ticket #3 — Custom WAF rules (paste-ready)
**Subject:** Add three custom WAF rules on fandomwire.com
**Body:**
> Please add these three WAF custom rules under the zone fandomwire.com, in the order specified, **above** existing rules, with the actions noted.
>
> **Rule 1 — Verified Bot Skip (priority 1):**
> ```
> Expression: cf.client.bot or (http.user_agent matches "Googlebot|Bingbot|Applebot|DuckDuckBot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|TelegramBot|WhatsApp")
> Action: Skip → All remaining custom rules, Rate Limiting Rules
> ```
>
> **Rule 2 — Cache-plugin allowlist (priority 2):**
> ```
> Expression: ip.geoip.asnum in {<ASN1> <ASN2>} or (http.user_agent contains "<cache-plugin-UA-token>")
> Action: Skip → All remaining custom rules, Rate Limiting Rules
> ```
> *(We'll provide the exact ASN list and UA once confirmed with our plugin vendor.)*
>
> **Rule 3 — Static signature block (priority 3):**
> ```
> Expression: http.user_agent contains "HeadlessChrome" or http.user_agent contains "Puppeteer" or http.user_agent contains "Playwright" or http.user_agent contains "phantomjs" or http.user_agent contains "Electron/" or http.user_agent eq ""
> Action: Block
> ```
>
> **Rule 4 — Chrome without client hints (priority 4):**
> ```
> Expression: (http.user_agent contains "Chrome/") and (not any(http.request.headers.names[*] eq "sec-ch-ua")) and (not cf.client.bot)
> Action: Managed Challenge
> ```
>
> Please start Rule 3 and Rule 4 in **Log** action for the first 24h, then promote to the actions above after we confirm no false positives.

### 4.4 Ticket #4 — Rate limits
**Subject:** Add three Rate Limiting Rules on fandomwire.com
**Body:**
> Please add these Rate Limiting Rules:
>
> 1. **Per-IP article rate limit:** 100 req/min on `http.request.uri.path matches "^/(?:[a-z0-9-]+)/?$"` → Managed Challenge for 5 min. Skip if `cf.client.bot`.
> 2. **Per-ASN total rate limit:** 5000 req/min/ASN excluding Verified Bots → Managed Challenge for 5 min.
> 3. **wp-login.php / xmlrpc.php protection:** 5 req/min on `http.request.uri.path matches "(wp-login\.php|xmlrpc\.php)"` → Block for 1h.

### 4.5 Ticket #5 — Honeypot path
**Subject:** Block /bot-trap path and tag offending IPs
**Body:**
> Please add: `http.request.uri.path eq "/bot-trap" or http.request.uri.path matches "^/bot-trap/"` → Block. We'll add the corresponding hidden anchor on our pages.

### 4.6 Ticket cadence
- Tickets #1 and #3 are highest priority — file together
- Ticket #2 (Logpush) often takes longest — file early
- Tickets #4, #5 after #3 is live and stable

---

## 5. Day-by-day execution

```
Day 1  (you, no permissions needed):
  - GA4 internal-traffic filter for cache-plugin IPs       (§3.1)
  - Ask "One Man Army" for IP/UA/header                     (§3.4)
  - File Cloudways Ticket #1 (Transform Rules)              (§4.1)
  - File Cloudways Ticket #2 (Logpush)                      (§4.2)

Day 2  (you, no permissions):
  - Deploy mu-plugin in fw-trust.php (§3.2) on staging
  - Run access-log triage from SSH                          (§3.3)
  - robots.txt hardened                                     (§3.6)

Day 3:
  - mu-plugin to production after staging sanity            (§3.2)
  - File Cloudways Ticket #3 (WAF rules) once you have ASN  (§4.3)

Day 4–5:
  - Verify Transform Rules headers arriving at origin
  - mu-plugin reads CF-Bot-Score; mu-plugin v2 deployed
  - GA4 internal-traffic filter promoted from Testing→Active

Day 6–8:
  - Cloudways Tickets #3 rules deployed in Log mode
  - Review 48h; promote to challenge/block
  - File Tickets #4, #5

Day 9–14:
  - Ship the beacon plugin                                  (§3.5)
  - Hook trust band into ad rendering
  - Run GA4 histogram check — confirm engagement-time recovery

Day 15+:
  - Logpush flowing; run the analysis-doc §6 queries
  - Address remaining bot residual after cache-plugin filtered out
  - Iterate
```

---

## 6. Specific to WordPress + Cloudways gotchas

| Gotcha | Why it matters | Fix |
|---|---|---|
| Cloudways CDN is **separate** from CF Enterprise add-on | The plain "Cloudways CDN" toggle uses a different vendor; only the CF Enterprise add-on gives you BotScore/Logpush | In Cloudways panel: Application → Cloudflare → confirm "Cloudflare Enterprise" is the active CDN, not "Cloudways CDN" |
| Cache plugin may bypass CF entirely on its origin probe | Some cache plugins hit the origin's real IP (not the CF-fronted hostname) to skip CDN caching while measuring | Confirm the crawler hits the CF hostname; if it hits origin IP directly, CF Enterprise rules can't see it and CF Bot Score won't be set |
| `REMOTE_ADDR` is Cloudways' load balancer, not the real visitor | Without `CF-Connecting-IP`, every visitor looks like a single IP | The mu-plugin already reads `CF-Connecting-IP` first; verify it's populated |
| Object cache (Redis on Cloudways) may serve cached pages without invoking mu-plugin guards | Bots get cached HTML even when mu-plugin would have suppressed analytics for them | Make sure the cache plugin **does not vary by** `FW_TRUST_BAND`; instead, suppress analytics in JS-side beacon-time, not server-render time (see note below) |
| Cloudflare High Security challenges Tor / VPN users hard | Real readers behind privacy tools may complain | This is expected; document it; no fix needed unless complaint volume is high |
| Cloudways auto-injects a `Server: nginx` header that contradicts your stack | Trivial fingerprint leak for attackers | Low priority; mention to Cloudways if they have a "remove server header" toggle |

**Note on caching + analytics suppression:** if a page is cached, the mu-plugin's `wp_head` action removal won't run on the cached response (the response is served from disk). So GA4 will still load. Two options:
- **Option A:** load GA4 via JS based on a server-set cookie that the mu-plugin sets. Cached pages all have the JS, but JS reads cookie/header to decide whether to fire `gtag`. This works but means GA4 only suppresses if the *first* request to set the cookie hit the mu-plugin.
- **Option B (better):** vary cache by `FW_TRUST_BAND` (basically two cache buckets: trusted vs everyone-else-no-analytics). Slightly more storage, but cleaner.

---

## 7. What this does NOT solve

- **Sophisticated residential-proxy attacks** that pass CF Enterprise's challenges. The mu-plugin can't beat what CF couldn't catch. Those need the trust-score beacon to bucket them into a soft-suspicious band where ads are off and GA4 is suppressed.
- **Direct origin IP attacks** that bypass Cloudflare entirely. If your origin IP is leaked, attackers hit it directly. Mitigation: rotate origin IP, restrict origin firewall to CF's published IP ranges (Cloudways can do this via Application → Security → IP Whitelisting, or via Cloudflare Authenticated Origin Pulls — Cloudways supports this in advanced plans).
- **`xmlrpc.php` / `wp-login.php` brute force**. CF Enterprise managed rules cover some; ticket #4 covers the rest.
- **Plugin-level vulnerabilities.** Unrelated; keep plugins current.

---

## 8. Success check (Day 7)

Run this checklist:
- [ ] GA4 engagement-time histogram shows a real human distribution (long tail, p50 > 10s)
- [ ] Internal-traffic filter is *Active* and is excluding > 50% of formerly-anomalous sessions
- [ ] mu-plugin is logging trust bands; `cache_crawler` band shows expected volume
- [ ] Cloudways access logs no longer dominated by Vietnam ASN IPs (cache crawler being soft-allowlisted at the origin, not visible in metrics)
- [ ] Server load on Cloudways down (no more wasted PHP renders for the cache crawler's targets)
- [ ] No SEO regression — Search Console Coverage report stable, Googlebot crawl rate stable
- [ ] Ad RPM trending up

If all green: phase 2 = ship the beacon and trust-score engine, address the residual real-bot share. If any red: don't escalate, diagnose.

---

## 9. Companion docs

- `docs/bot-traffic-forensic-analysis.md` — the why, queries, threat model (still valid)
- `docs/bot-traffic-protection-plan.md` — the full-CF-access version (partially applicable; treat as target state)
- `docs/addendum-cache-plugin-lead.md` — cache-plugin hypothesis (drives §3.1, §3.4, §4.3 Rule 2)
- **this document** — execution under the actual constraints

---

*Bottom line: under Cloudways CF Enterprise (managed) + WordPress, the single most impactful action today is GA4 internal-traffic filtering of the cache-plugin IPs (§3.1), followed by the mu-plugin (§3.2), followed by Ticket #1 (Transform Rules) so the mu-plugin can use real BotScore. Everything else is incremental on top of those three.*
