# How to Stop It — Execution Guide

**Two problems, two fixes, both in one mu-plugin. No Cloudflare access required.**

| Problem | Fix | Where |
|---|---|---|
| **A. Cache-plugin Puppeteer crawler poisoning analytics** | Tag the traffic, strip GA4 and ad code server-side. Don't block. | mu-plugin + GA4 internal-traffic filter |
| **B. UA spoofers claiming to be Googlebot / Meta-AI / OAI-SearchBot** | Reverse-DNS verify every declared bot UA. Block on failure. | mu-plugin |

The actual code is in `wordpress/mu-plugins/fw-bot-defense.php` (drop in unchanged).

---

## Day 1 — Ship in this order

### Step 1 — Get three pieces of intel from "One Man Army" (5 min)

Send him this:

> "Three things I need to allowlist your crawler cleanly:
>  1. Egress IP range / CIDR (the IPs the Puppeteer fleet runs from)
>  2. The exact `User-Agent` string the crawler sends
>  3. Can the crawler send a shared-secret header on every request? e.g. `X-Cache-Gen: <secret>` — that would make the allowlist cryptographic instead of heuristic"

If he sends a UA token: confirm it's already in `FW_CACHE_CRAWLER_UA_TOKENS` at the top of the mu-plugin; if not, add it.
If he sends IPs: paste into `wordpress/mu-plugins/cache-crawler-ips.php`.
If he sends a secret: set `FW_CACHE_CRAWLER_SECRET` to its value.

### Step 2 — Populate the AI-vendor IP ranges (5 min)

```bash
cd wordpress/scripts
./update-bot-ip-ranges.sh > ../mu-plugins/published-ip-ranges.php
```

This pulls fresh CIDRs from `openai.com/gptbot.json`, `openai.com/searchbot.json`, and `openai.com/chatgpt-user.json`. Add Anthropic + Perplexity ranges manually from their docs until they publish JSON.

Add this to weekly cron on Cloudways:
```cron
0 6 * * 1  /home/master/applications/<app>/private_html/update-bot-ip-ranges.sh > /home/master/applications/<app>/public_html/wp-content/mu-plugins/published-ip-ranges.php
```

### Step 3 — Deploy the mu-plugin to STAGING first (15 min)

```bash
# From Cloudways SSH on the staging app:
cd /home/master/applications/<staging-app>/public_html/wp-content
mkdir -p mu-plugins
# Upload the three files via SFTP / SCP:
#   fw-bot-defense.php
#   cache-crawler-ips.php
#   published-ip-ranges.php
```

**Verify in staging:**
```bash
# Trusted human
curl -sI -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' \
     -H 'sec-ch-ua: "Chromium";v="124"' https://staging.fandomwire.com/ | grep -i x-fw
# Expected: (no X-FW header — trusted band, no special handling)

# Headless Chrome → should 403
curl -sI -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0 Safari/537.36' \
     https://staging.fandomwire.com/ | head -3
# Expected: HTTP/2 403 ... X-FW-Block: signature_block

# Spoofer claiming Googlebot from random IP → should 403
curl -sI -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
     https://staging.fandomwire.com/ | head -3
# Expected: HTTP/2 403 ... X-FW-Block: spoof:Googlebot
# (Assuming the curl is run from a random IP, not from Google's actual crawl ranges.)

# Cache-crawler UA → should pass with cache_crawler band
curl -sI -A 'Mozilla/5.0 FlyingPress/1.0' https://staging.fandomwire.com/ | grep -i x-fw
# Expected: X-FW-Trust: cache_crawler

# WP admin should be untouched
curl -sI 'https://staging.fandomwire.com/wp-admin/' | head -3
# Expected: 302 or 200 (no 403)
```

**If any test fails:** check `error_log` for PHP warnings; the mu-plugin's `fw_real_ip()` may be picking up the wrong header (Cloudways usually forwards `CF-Connecting-IP` correctly, but verify).

### Step 4 — Ship to production (10 min)

Same three files, same path. Watch the access log for 5 minutes:

```bash
tail -f /home/master/applications/<prod-app>/logs/apache_<prod-app>.access.log | grep ' 403 '
```

If 403s spike beyond expected bot rate (a few hundred per hour is normal; thousands per minute is not), the spoofer fingerprint is firing on legitimate traffic — `ESC`, comment out the `fw_403('spoof:...')` line and reload to convert blocks to logged-passes for triage.

### Step 5 — GA4 internal-traffic filter (15 min)

GA4 → **Admin** → **Data Streams** → web stream → **Configure tag settings** → **Show all** → **Define internal traffic**

- Rule name: `cache-plugin-crawler`
- Traffic type value: `internal`
- Match type: **IP address in range** (or **in CIDR range**)
- Paste the cache-plugin IPs from Step 1

Then **Admin** → **Data Settings** → **Data Filters** → **Create filter**
- Type: **Internal traffic**
- State: **Testing** for 48h, then **Active**

Result: within 24h of going Active, the cache-crawler sessions stop appearing in standard GA4 reports → engagement-time metric recovers.

### Step 6 — robots.txt updates (5 min)

In WordPress (Yoast/RankMath custom robots editor or `wp-content/themes/<theme>/robots.txt`):

```
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: PerplexityBot
Disallow: /

User-agent: Omgilibot
Disallow: /

User-agent: ImagesiftBot
Disallow: /

Sitemap: https://fandomwire.com/sitemap.xml
```

This (a) removes legal exposure for AI training, (b) is required before escalating to WAF blocks for these agents.

---

## Day 2 — File the Cloudways tickets

Three tickets, all paste-ready. File **#1 first** — the others build on it.

### Ticket #1 — Forward Cloudflare signals to origin

**Subject:** Enable Cloudflare Managed Transforms to forward BotScore + ASN + Verified Bot headers to origin
**Body:**
> Please enable the following Managed Request Header Transforms (or equivalent Transform Rules) on the zone for fandomwire.com so that the following headers are added to all requests forwarded to our origin:
>
> - `CF-Bot-Score`: from `cf.bot_management.score`
> - `CF-Verified-Bot`: from `cf.client.bot`
> - `CF-IPASN`: from `ip.geoip.asnum`
> - `CF-Threat-Score`: from `cf.threat_score`
> - `CF-JA3-Hash`: from `cf.bot_management.ja3_hash` (Enterprise Bot Management feature)
>
> These are standard Enterprise plan fields. No rule action is needed — only the transform that adds them as request headers.

Once these arrive at the origin, the mu-plugin can read `CF-Bot-Score` and make better decisions than UA-based heuristics. (We'll ship a v2 of the plugin that uses them.)

### Ticket #2 — Add three custom WAF rules

**Subject:** Add three custom WAF rules on fandomwire.com (paste-ready expressions)
**Body:**
> Please add these custom rules in this exact order, **above** any existing custom rules. Start each new rule in **Log** action; we'll request promotion after 24h.
>
> **Rule 1 (priority 1) — Verified bot skip:**
> ```
> Expression: cf.client.bot or (http.user_agent matches "Googlebot|Bingbot|Applebot|DuckDuckBot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|TelegramBot|WhatsApp")
> Action: Skip → All remaining custom rules + Rate Limiting Rules
> ```
>
> **Rule 2 (priority 2) — Cache-plugin allowlist:**
> ```
> Expression: ip.geoip.asnum in {<ASN1> <ASN2>} or (http.user_agent contains "<CACHE_CRAWLER_UA>")
> Action: Skip → All remaining custom rules + Rate Limiting Rules
> ```
> *(We will provide the exact ASN list and UA in a follow-up once verified.)*
>
> **Rule 3 (priority 3) — Static signature block:**
> ```
> Expression: http.user_agent contains "HeadlessChrome" or http.user_agent contains "Puppeteer" or http.user_agent contains "Playwright" or http.user_agent contains "phantomjs" or http.user_agent contains "Electron/" or http.user_agent eq ""
> Action: Block
> ```
>
> **Rule 4 (priority 4) — Spoofed bot challenge:**
> ```
> Expression: (http.user_agent matches "Googlebot|Bingbot|Applebot|Meta-ExternalAgent|GPTBot|ClaudeBot|PerplexityBot") and not cf.client.bot and not (ip.geoip.asnum in {15169 8075 714 32934})
> Action: Managed Challenge
> ```
> (15169 = Google, 8075 = Microsoft, 714 = Apple, 32934 = Meta. Add OpenAI/Anthropic ASNs once they publish them.)

### Ticket #3 — Rate limiting + honeypot

**Subject:** Add 3 rate-limiting rules and a honeypot path block
**Body:**
> Please add the following Rate Limiting Rules:
>
> 1. `http.request.uri.path matches "^/[a-z0-9-]+/?$"`: 100 req/min per IP → Managed Challenge for 5 min. Skip if `cf.client.bot`.
> 2. `not cf.client.bot`: 5000 req/min per ASN → Managed Challenge for 5 min.
> 3. `http.request.uri.path matches "(wp-login\.php|xmlrpc\.php)"`: 5 req/min per IP → Block for 1 hour.
>
> Plus one custom rule:
> 4. `http.request.uri.path eq "/bot-trap" or http.request.uri.path matches "^/bot-trap/"` → Block.

---

## Day 3+ — Validation

### Run these three queries against Cloudways access logs to confirm impact:

```bash
APP=<your-cloudways-app-name>
LOG=/home/master/applications/$APP/logs/apache_$APP.access.log
TODAY=$(date '+%d/%b/%Y')

# 1. 403 rate (mu-plugin blocking spoofers)
echo "Blocks today:"
grep " 403 " $LOG | grep "$TODAY" | wc -l

# 2. Top blocked UAs
echo; echo "Top blocked UA strings:"
grep " 403 " $LOG | grep "$TODAY" | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -10

# 3. Top IPs claiming bot identity but blocked
echo; echo "Top blocked IPs:"
grep " 403 " $LOG | grep "$TODAY" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### Verify GA4 engagement-time recovered:

GA4 → Reports → Engagement → Engagement overview → check "Average engagement time per active user" trend. Should rise from ~1s toward a real human value over 24–72h after the internal-traffic filter goes Active.

For a sharper check, run this in GA4 Explorations: histogram of `engagement_time_msec` bucketed by 1s. Should change from a delta-function at 1s to a long-tail distribution centered at 10–30s.

### Confirm Googlebot isn't being blocked:

```bash
grep "Googlebot" $LOG | grep "$TODAY" | awk '{print $9}' | sort | uniq -c
# Expected: overwhelmingly 200/304, near-zero 403.
# If 403s appear: legitimate Googlebot is reverse-DNS-failing, which means either
#  (a) DNS resolver on Cloudways is slow/broken → check resolv.conf
#  (b) the transient cache wrote 'spoof' during a transient DNS error → flush wp_options where option_name LIKE '_transient_fw_bot_%'
```

---

## What this stops, what it doesn't

**Stops:**
- Cache-plugin Puppeteer pollution of GA4 (Story 1)
- Anyone claiming to be Googlebot/Bingbot/Applebot/Meta-AI/etc. from a non-vendor IP (Story 2)
- Headless Chrome / Puppeteer / Playwright / phantomjs identifying themselves honestly
- Chrome UAs missing `sec-ch-ua` (analytics + ads stripped, page still served)

**Does not stop:**
- Sophisticated residential-proxy traffic with valid `sec-ch-ua` and no bot UA claim → trust-score beacon needed (Phase 2 of main protection plan)
- Direct origin-IP attacks bypassing Cloudflare → restrict origin firewall to CF IP ranges (Cloudways app → Application Settings → Security → Whitelisted IPs)
- Page-cache hits where the mu-plugin never runs → for cached HTML, the GA4 script still loads; for full coverage, vary the cache by `FW_TRUST_BAND` (see cloudways playbook §6) or read trust band client-side from a cookie

---

## Rollback procedure

If anything breaks:

```bash
# Disable mu-plugin instantly (no need to redeploy)
mv /home/master/applications/<app>/public_html/wp-content/mu-plugins/fw-bot-defense.php \
   /home/master/applications/<app>/public_html/wp-content/mu-plugins/fw-bot-defense.php.disabled

# Flush all bot verification transients
wp transient delete --all
# or via SQL:
# DELETE FROM wp_options WHERE option_name LIKE '\_transient\_fw\_bot\_%' OR option_name LIKE '\_transient\_timeout\_fw\_bot\_%';
```

GA4 internal-traffic filter can be paused from Admin → Data Filters → set state to **Inactive**.

Cloudways WAF rule rollback: ticket Cloudways with "please disable rule X."

---

## Order of operations (one-line summary)

1. Get cache-crawler IP/UA from "One Man Army"
2. Update `cache-crawler-ips.php` + `published-ip-ranges.php` (via script)
3. Drop the three files into `wp-content/mu-plugins/` on staging → test → production
4. GA4 internal-traffic filter → Testing → Active
5. robots.txt for AI crawlers
6. File Cloudways tickets #1 (transforms), #2 (WAF rules), #3 (rate limits)
7. Run validation queries on Day 3

Total elapsed time end-to-end: **~3 days**, of which only **~2 hours is hands-on**. The rest is waiting for Cloudways tickets to land and for GA4 to ingest 24h of filtered data.
