# Reverse-Engineering the Crawler — Tactical Playbook

**Goal:** Without taking the plugin developer's word for it, independently identify the **exact service** hitting FandomWire, build a high-precision fingerprint (IP, UA, JA3, headers, behavior, timing), and prove it is benign Used-CSS generation (or expose that it isn't).

**Why bother:** an allowlist built on hearsay can be subverted by an attacker who mimics the same UA. A fingerprint built on **multiple independent signals that the attacker can't simultaneously control** (egress IP + JA3 + path-coverage pattern + request timing) is robust.

**Method:** seven probes, each producing one or more orthogonal signals. Cross-correlate. A real cache-plugin crawler matches all of them; a spoofer matches at most two.

---

## 1. Phase A — Passive external recon (1 hour, no access to WP admin needed)

Identify which cache plugin is in front of FandomWire purely from outside.

### A1. View source for footprints
```bash
curl -sLA 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' \
  https://fandomwire.com/ -o /tmp/fw-home.html

# Cache-plugin generator tells
grep -E -o '(flying-press|wp-rocket|litespeed|nitropack|w3-total-cache|swift-performance|hummingbird|perfmatters|wp-optimize|cache-enabler|autoptimize|breeze|sg-optimizer)' /tmp/fw-home.html | sort -u

# Look for explicit signature comments (FlyingPress and WP Rocket both leave one)
grep -E '<!-- (.*[Ff]lying[Pp]ress|This website is like a Rocket|Optimized by WP Rocket|Optimized by NitroPack|cached by W3 Total Cache).* -->' /tmp/fw-home.html
```

### A2. Asset path inspection
```bash
# Inline + linked CSS/JS reveal cache plugin
grep -oE '/wp-content/[^"]*\.(css|js)[^"]*' /tmp/fw-home.html | sort -u | head -40

# Telltale paths:
#   /wp-content/cache/flying-press/        → FlyingPress
#   /wp-content/cache/min/                 → WP Rocket / Better WordPress Minify
#   /wp-content/litespeed/                 → LiteSpeed Cache
#   /wp-content/cache/swift-performance/   → Swift Performance
#   /wp-content/cache/breeze-minification/ → Breeze
#   /wp-content/uploads/sgo-optimizer/     → SG Optimizer
#   /wp-content/nitro/                     → NitroPack
#   /wp-content/cache/autoptimize/         → Autoptimize
```

### A3. Response header inspection
```bash
curl -sIA 'Mozilla/5.0 Chrome/124' https://fandomwire.com/ | grep -iE 'x-cache|x-flying|x-rocket|x-litespeed|x-nitro|x-cached-by|server|x-powered-by|cf-cache|cf-ray'

# Headers to look for:
#   x-cached-by: WP-Rocket            → WP Rocket
#   x-flying-press: HIT|MISS          → FlyingPress
#   x-litespeed-cache: hit            → LiteSpeed
#   x-nitro-cache: hit                → NitroPack
```

### A4. JavaScript runtime tells
Open DevTools on fandomwire.com:
- Console: `Object.keys(window).filter(k => /flying|rocket|nitro|lite|wpo/i.test(k))`
- Performance tab → look for inline scripts named `flying-pages`, `wp-rocket-lazy`, `nitro-stack`, `lscwp`
- Network tab → filter `.css`; observe lazy/async-loaded "used CSS" sheet name (FlyingPress: `flying-press.min.css`; WP Rocket RUCSS: `<hash>.css` from `wp-content/cache/used-css/`)

### A5. wp-json fingerprint (occasionally exposes plugin list)
```bash
curl -s 'https://fandomwire.com/wp-json/' | jq '.routes | keys[]' 2>/dev/null | grep -iE 'flying|rocket|litespeed|nitro|optimize|cache'

# wp-json may also have:
curl -s 'https://fandomwire.com/wp-json/wp/v2/users' | jq    # exposes admins if not blocked
```

**Output of Phase A:** a confident name of the cache plugin (e.g., "FlyingPress 4.x"). Most CSS optimization plugins are identifiable in < 5 minutes.

---

## 2. Phase B — Identify the backend service (15 min, needs WP admin)

Most cache plugins delegate Used-CSS / Critical-CSS generation to a **remote API**. The crawler hitting your site is operated by that API vendor, not by the plugin author personally. Identifying the vendor is what gives you the egress IP list.

### B1. Plugin source grep
SSH into Cloudways and grep the installed plugin for the remote API base URL:
```bash
cd /home/master/applications/<app>/public_html/wp-content/plugins/<cache-plugin>/
grep -RInE 'https?://[a-z0-9.-]+\.(com|io|net|cloud|app|dev)(/[a-z0-9/-]*)?' --include='*.php' --include='*.js' \
  | grep -viE '(schema|w3|wp\.org|wordpress\.org|fonts\.google|cdnjs|jquery|github|example)' \
  | sort -u
```

Typical findings:
- FlyingPress → `https://api.flyingpress.com/`
- WP Rocket RUCSS → `https://saas.wp-rocket.me/` and `https://app.wp-rocket.me/`
- NitroPack → `https://api.nitropack.io/`
- LiteSpeed QUIC.cloud → `https://api.quic.cloud/`
- Perfmatters → `https://perfmatters.io/api/`

### B2. WP-CLI live trace
```bash
wp option list --search='*api*' --format=csv | grep -i '<cache-plugin>'
wp option list --search='*license*' --format=csv | grep -i '<cache-plugin>'
wp option list --search='*used_css*' --format=csv
# also:
wp option get <cache-plugin-options-key> --format=json | jq | grep -E 'api|service|url'
```

### B3. Watch outbound traffic
Enable HTTP request logging temporarily via the **Query Monitor** plugin or:
```php
// drop into a tiny mu-plugin
add_action('http_api_curl', function ($handle, $args, $url) {
  error_log("OUTBOUND: $url");
}, 10, 3);
```
Trigger a "Regenerate Used CSS" action in the cache plugin admin UI. The vendor's API host shows up in the error log within seconds.

### B4. Probe the discovered API
```bash
# DNS + IP
dig api.flyingpress.com +short
dig +short -t TXT api.flyingpress.com   # often reveals SaaS infra (Cloudflare, Vercel, etc.)

# whois on the IP
whois $(dig +short api.flyingpress.com) | grep -iE 'origin|netname|country|orgname'
```

Note that the **API endpoint** is typically behind Cloudflare itself — the egress crawler IPs are different. The next phase finds the egress.

---

## 3. Phase C — Active probing (the most powerful step)

You control whether the crawler runs. **Trigger it on a known URL while watching origin logs.** This is how we get the egress IP, JA3 (via a controlled endpoint), and the request fingerprint, all in one shot.

### C1. Deploy a canary endpoint
On the WordPress origin, add a single tracking page:

```php
// wp-content/mu-plugins/fw-canary.php
add_action('init', function () {
    if ($_SERVER['REQUEST_URI'] !== '/fw-canary-' . sha1('seed-2026-05')) return;
    $log = [
        't'    => microtime(true),
        'ip'   => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'],
        'ua'   => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'hdrs' => array_filter($_SERVER, fn($k) => str_starts_with($k, 'HTTP_'), ARRAY_FILTER_USE_KEY),
        'cf_score' => $_SERVER['HTTP_CF_BOT_SCORE'] ?? null,
        'cf_asn'   => $_SERVER['HTTP_CF_IPASN'] ?? null,
        'q'    => $_SERVER['QUERY_STRING'] ?? '',
    ];
    file_put_contents('/home/master/applications/<app>/private_html/fw-canary.jsonl',
                      json_encode($log) . "\n", FILE_APPEND);
    // Serve a tiny page with one external CSS, one external JS, and one tracking pixel — so the
    // crawler exercises its full pipeline (Coverage on CSS, JS execution, image fetch decision).
    header('Content-Type: text/html');
    echo '<!doctype html><html><head><meta charset=utf-8>'
       . '<link rel=stylesheet href="/wp-content/themes/active/style.css?canary=1">'
       . '<script src="/wp-content/themes/active/script.js?canary=1" defer></script>'
       . '</head><body><h1>Canary</h1>'
       . '<img src="/canary-pixel.gif?id=' . uniqid() . '" alt="">'
       . '<a href="/fw-canary-honeypot" style="position:absolute;left:-9999px">x</a>'
       . '</body></html>';
    exit;
});
```

### C2. Force the cache plugin to crawl the canary
Add the canary URL to the cache plugin's known URL list:
- **FlyingPress:** Settings → Cache → URL Cache Includes → add the canary URL → click "Preload" or "Regenerate Used CSS"
- **WP Rocket:** Tools → Used CSS → Clear Used CSS → trigger preload
- **NitroPack:** Dashboard → Optimization → Manually optimize URL
- **LiteSpeed:** Toolbox → Purge → Purge by URL → re-crawl

Within 30–120s, the canary's jsonl log captures **exactly the crawler's request** with no noise.

### C3. Extract the signature
```bash
cat /home/master/applications/<app>/private_html/fw-canary.jsonl | jq '.'
```
You now have:
- **Egress IP**
- **Full User-Agent string** (which may include version, build hash, or vendor token)
- **Every HTTP header** (Accept, Accept-Language, Accept-Encoding, sec-ch-ua, sec-fetch-*, referer)
- **CF-Bot-Score** (if Transform Rule from earlier ticket is live)
- **CF-IPASN**

```bash
# Reverse-DNS the egress IP
dig -x <egress_ip>
# whois the egress IP
whois <egress_ip> | grep -iE 'orgname|netname|country|origin|asn|descr'
# IP geo
curl -s "https://ipapi.co/<egress_ip>/json/" | jq
# ASN history
curl -s "https://stat.ripe.net/data/whois/data.json?resource=<egress_ip>" | jq '.data.records'
```

Cross-check against the cache-plugin's official documentation page (vendors usually publish their egress IP list — search `"<plugin-name>" "whitelist" "IP"`). If your discovered egress matches their published list → confirmed. If it doesn't → suspicious (the actor may be impersonating).

### C4. Trigger N more times across different pages
Repeat C2 with 3–5 different canary URLs. Observations to record:

| Observation | What it tells you |
|---|---|
| Same egress IP every time | Single instance backend |
| Cycling egress IPs from a fixed /24 | Pooled backend, identifiable by CIDR |
| Same JA3 every time | Same Puppeteer build → reliable fingerprint |
| Same request timing offset from cache-plugin admin click | Synchronous architecture (rare) |
| Async with stable delay | Queue-based architecture, common for SaaS Used-CSS services |
| Different User-Agent across pages | Spoofed UA pool → less trustworthy |
| Honeypot anchor visited | Crawler follows hidden links → not a "real headless browser" emulation; cheap scraper |

---

## 4. Phase D — Puppeteer build fingerprint

If you control a canary, you can fingerprint *which* Puppeteer build (or which patched fork) the crawler runs.

### D1. Serve a fingerprint JS payload
Replace the canary's `<script>` with this — it writes browser intrinsics to a POST endpoint:

```js
(async () => {
  const fp = {
    ua: navigator.userAgent,
    appVersion: navigator.appVersion,
    wd: navigator.webdriver,
    langs: navigator.languages,
    plugins: Array.from(navigator.plugins).map(p => p.name),
    mimeTypes: Array.from(navigator.mimeTypes).map(m => m.type),
    hardware: navigator.hardwareConcurrency,
    memory: navigator.deviceMemory,
    permissions: typeof navigator.permissions,
    chromeObj: typeof window.chrome,
    chromeRuntime: !!(window.chrome && window.chrome.runtime),
    chromeLoadTimes: !!(window.chrome && window.chrome.loadTimes),
    canvas: (() => {
      try {
        const c = document.createElement('canvas');
        const ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fp-probe-2026', 2, 2);
        return c.toDataURL().slice(-32);
      } catch (e) { return 'err:' + e.message; }
    })(),
    webgl: (() => {
      try {
        const g = document.createElement('canvas').getContext('webgl');
        const dbg = g.getExtension('WEBGL_debug_renderer_info');
        return [g.getParameter(dbg.UNMASKED_VENDOR_WEBGL), g.getParameter(dbg.UNMASKED_RENDERER_WEBGL)];
      } catch (e) { return 'err'; }
    })(),
    audio: (() => {
      try {
        const a = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
        const o = a.createOscillator(); o.connect(a.destination); o.start(0);
        return a.startRendering ? 'ok' : 'no-render';
      } catch (e) { return 'err'; }
    })(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    fonts: (() => {
      const test = ['Arial', 'Helvetica', 'Courier New', 'Comic Sans MS', 'Calibri', 'Cantarell'];
      return test.filter(f => document.fonts.check(`12px "${f}"`));
    })(),
    nav: Object.getOwnPropertyNames(Navigator.prototype),
    win: Object.getOwnPropertyNames(window).filter(k => /webdriver|cdc|driver|playwright|puppeteer/i.test(k)),
  };
  fetch('/wp-json/fw-canary/v1/fp', { method: 'POST', body: JSON.stringify(fp), keepalive: true });
})();
```

The matching REST route writes the FP JSON to disk. Within one regen cycle you'll have a complete browser intrinsics dump.

### D2. Diagnostic signals in the dump

| Signal | Real Chrome | Stock Puppeteer | Stealth Puppeteer | Playwright |
|---|---|---|---|---|
| `navigator.webdriver` | `undefined` | `true` | `false` (patched) | `true` |
| `navigator.languages.length` | 2–4 | 1 | 2–4 (patched) | 1 |
| `navigator.plugins.length` | 3–5 | 0 | 3+ (faked) | 0 |
| `window.chrome.runtime` exists | true | **false** | true (faked) | false |
| `chrome.loadTimes` exists | true | false | true (faked) | false |
| `window.cdc_*` properties | none | none | none | **present** |
| `WebGL vendor` | NVIDIA/Intel/AMD | "Google Inc. (Google)" | varies | "Google Inc." |
| AudioContext fingerprint | device-specific | constant | constant | constant |
| Permissions API consistency | normal | `notification` returns wrong state | patched | wrong |

Puppeteer-stealth in particular leaves traces in *which* properties are patched — the patches are detectable by enumeration order, as in:
```js
Object.getOwnPropertyDescriptor(navigator, 'webdriver')
// real: undefined / not own property
// patched: {get: ƒ, configurable: true, enumerable: false}
```

A clean cache-plugin Puppeteer build typically:
- Does not bother with stealth (it's not trying to evade detection — it's an honest service)
- Has `webdriver = true`
- Has empty plugins
- Has WebGL vendor "Google Inc."

If the FP dump shows **stealth signatures** (patched `webdriver`, faked plugins), that's a strong signal this is **not** a benign cache-plugin crawler — it's something pretending to be one.

---

## 5. Phase E — Behavioral signature

The Coverage API has a distinctive runtime pattern. Confirm we're seeing it:

### E1. Coverage-mode timing
A Puppeteer Coverage run does:
1. `page.coverage.startCSSCoverage()` / `startJSCoverage()`
2. `page.goto(url, { waitUntil: 'load' or 'networkidle0' })`
3. Wait until network idle (typically ~500–1500ms after `DOMContentLoaded`)
4. `page.coverage.stop*Coverage()` (synchronous)
5. `browser.close()` / `page.close()`

Total: **0.7–1.5 seconds** for a typical article page. Matches your 0.98s observation almost exactly.

A real reader: page load + scroll + read → **8–30s** before unload.

### E2. Resource fetch pattern
Coverage requires **all stylesheets and scripts to load fully** (so Coverage can report which bytes were used). It does **not** require images, fonts, or media to load. Pattern:

- CSS files: all loaded
- JS files: all loaded and executed
- Images: lazy-load disabled by Coverage's wait condition; eager-loaded images fetched, lazy ones often not
- Web fonts: usually fetched
- Ads / analytics: depends on the plugin's `networkidle0` definition — if cache-plugin uses `setRequestInterception` to block ad URLs, ads don't fetch; otherwise they do

Diagnostic SQL on access logs:
```sql
-- per-IP asset-type ratio
SELECT
  client_ip,
  COUNT(*) AS total_req,
  COUNTIF(REGEXP_CONTAINS(path, r'\.(css)($|\?)')) AS css,
  COUNTIF(REGEXP_CONTAINS(path, r'\.(js)($|\?)')) AS js,
  COUNTIF(REGEXP_CONTAINS(path, r'\.(jpg|png|webp|avif|gif|svg)($|\?)')) AS img,
  COUNTIF(REGEXP_CONTAINS(path, r'\.(woff2?|ttf|eot)($|\?)')) AS font,
  COUNTIF(REGEXP_CONTAINS(path, r'(googletagmanager|google-analytics|doubleclick|adsbygoogle)')) AS ad_anly
FROM `<your_log_table>`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY client_ip
HAVING total_req > 50
ORDER BY total_req DESC
LIMIT 50;
```

A cache-plugin crawler looks like:
- High `css` and `js` per page
- Low or zero `img`
- Low or zero `font`
- Variable `ad_anly` (vendor-dependent)
- Hits each path exactly once (`COUNT(*) / COUNT(DISTINCT path) ≈ 1.0`)

A real reader:
- Variable `css`/`js` (cached)
- High `img`
- Some `font`
- High `ad_anly`
- Revisits pages

A malicious scraper:
- Variable
- Usually skips assets entirely (faster)
- Hits content paths repeatedly or follows specific category paths

### E3. Path sequencing
Cache-plugin crawlers walk URLs in **sitemap order or post-ID order**. Plot path sequence vs. request order — if it's monotonic by sitemap position, it's a crawler. Real users are scattered.

```bash
# requires sitemap parsed
awk '{print $1, $4, $7}' apache_<app>.access.log \
  | awk -v ip="<suspect_ip>" '$1 == ip {print $3}' \
  | head -200
# eyeball: are paths walking the catalog in order?
```

---

## 6. Phase F — JA3 / TLS fingerprint (requires CF Transform Rule from Cloudways ticket #1)

Once `CF-JA3-Hash` arrives at the origin, log it per request from the canary. Then:

```bash
# Cross-reference JA3 against known Puppeteer / Chromium builds
# Free public JA3 databases:
curl -s "https://ja3er.com/search/<ja3-hash>" | jq

# A canonical Puppeteer JA3 for Chromium 119+ looks like one of:
#   771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,...
# Hashed value example (varies by build): 'b32309a26951912be7dba376398abc3b'
```

A **single JA3** spanning many IPs in the suspect range is **definitive** — TLS fingerprints aren't trivially mutable by attackers without modifying Chromium itself. Compare:

- Canary-captured JA3 (from cache-plugin invocation)
- Top-volume JA3 in normal anomalous traffic

If they match → **same client**. If different → **different actors, both running headless Chrome**. The latter is likely (one is the cache plugin, the other is a real scraper).

---

## 7. Phase G — Cross-validation against the developer's claim

Now compare what you found vs. what "One Man Army" said:

| Claim | Source | Verified by |
|---|---|---|
| "Uses Puppeteer" | Developer | Browser intrinsics dump (D2) |
| "From Vietnam servers" | Developer | Egress IP whois + ASN (C3) |
| "For Used CSS generation" | Developer | Coverage-API timing + path coverage (E1, E3) |
| "Same architecture as Gijo's plugin" | Developer | API endpoint resolves to same vendor pattern (B1) — or independent provider |
| "Not an attack" | Developer | Path coverage pattern is monotonic + sitemap-aligned + JA3 single + asset ratio matches cache-plugin (E2) |

**If all 5 match:** confirmed benign Used-CSS crawler. Allowlist by IP CIDR + UA + JA3, file Cloudways Ticket #3 Rule 2 with the verified signature, ship the GA4 internal-traffic filter.

**If 4 match:** likely benign, but allowlist by **at least two orthogonal signals** (e.g., IP **and** JA3), not just UA.

**If ≤ 3 match:** treat as suspicious until further investigation. Path coverage being non-monotonic is the strongest "not really a cache plugin" signal.

---

## 8. Output artifact — the canonical fingerprint document

After phases A–G, produce one structured artifact:

```yaml
# docs/fingerprints/<vendor>-cache-crawler.yaml
vendor:
  name: <vendor-name>
  service_endpoint: https://api.<vendor>.<tld>/
  api_resolved_to_provider: <CF/Vercel/AWS/etc.>
  cache_plugin_consumer: <FlyingPress / WP Rocket / NitroPack / etc.>
  installed_version_seen: <plugin version>

egress:
  asn:
    - { number: <ASN>, name: <name>, country: VN }
  cidrs:
    - <a.b.c.d/24>
    - <e.f.g.h/24>
  rdns_pattern: <regex on rDNS, often ".*-puppeteer.*" or hosting provider's PTR>

http_signature:
  user_agent: <exact UA string>
  user_agent_pattern: <regex if rotates>
  required_headers_present:
    - accept-encoding
    - accept
  headers_typically_missing:
    - sec-ch-ua
    - sec-ch-ua-mobile
    - sec-ch-ua-platform
  optional_custom_header: # if vendor implements it
    name: X-<Vendor>-Crawler
    value_pattern: <regex>

tls_signature:
  ja3: <hash>
  ja4: <hash>
  ja3_seen_across_n_ips: <number>
  ja3_seen_in_other_traffic: <yes/no>   # if yes, fingerprint not unique

browser_signature:
  webdriver: true
  languages_length: 1
  plugins_length: 0
  chrome_runtime: false
  webgl_vendor: "Google Inc. (Google)"
  audiocontext_fp: <hash>

behavioral_signature:
  request_per_page: { css: ">=3", js: ">=3", img: "<=1", font: "0-2" }
  path_repeat_factor: 1.0
  path_order: monotonic_sitemap
  honeypot_followed: false
  ad_endpoints_called: false
  ga4_endpoints_called: true   # this is why your engagement metric is poisoned
  total_session_duration_ms: { p50: 950, p95: 1500 }

trust_decision:
  allowlist: true
  allowlist_method: "IP CIDR + JA3 (both must match)"
  ga4_filter: true
  ad_render: false
  log_band: cache_crawler

confidence: 0.95
last_verified: 2026-05-13
verifier: <person>
re-verify_cadence: quarterly
```

Drop this file into `docs/fingerprints/`. Re-verify quarterly because plugin vendors update their backends and egress fleets.

---

## 9. Tooling check (install once on Cloudways)

```bash
# Already on Cloudways: curl, dig, whois, grep, awk, jq
# Add if missing:
apt-get install -y jq tcpdump tshark openssl

# For JA3 from raw capture (advanced — only if Transform Rules can't be enabled):
# tcpdump -i any -w /tmp/cap.pcap port 443
# tshark -r /tmp/cap.pcap -Y 'tls.handshake.type == 1' \
#        -T fields -e ip.src -e tls.handshake.ja3 -e tls.handshake.ja3_full
```

`tshark` JA3 capture is a workaround if you can't get the CF transform — captures TLS ClientHello directly from origin's incoming packets. Limited to traffic that didn't get terminated at CF (which means: only direct-to-origin traffic, useful only if origin IP is leaked).

---

## 10. Daily ops after fingerprint is built

1. **Monitor for fingerprint drift.** Plugin vendors update their Puppeteer fleet — UA may change, IPs may rotate. Re-run §C2 monthly to confirm.
2. **Alert if traffic matches "vendor IP" but "wrong JA3".** This is the highest-value alert in the system: an attacker squatting on a known-trusted IP range with the wrong TLS fingerprint.
3. **Alert if traffic matches "vendor UA + wrong IP".** UA is trivially spoofed; this catches impersonators.
4. **Document the cross-product.** A small matrix (IP class × JA3 × UA × behavioral fit) makes "is this thing legit" a 30-second decision.

---

## 11. Common cache-plugin / Used-CSS vendor egress profiles (starting points)

Use these only as *priors* until you've verified with §C. Do not allowlist by these alone.

| Vendor | Known egress ASN(s) historically | Notes |
|---|---|---|
| FlyingPress / CriticalCSS.com (Gijo) | Hetzner (AS24940), DigitalOcean (AS14061), occasionally Vultr (AS20473) | Run by Gijo Varghese; small fleet |
| WP Rocket RUCSS (WP Media) | Google Cloud (AS15169), AWS (AS16509) | Larger fleet, distributed |
| NitroPack | NitroPack-owned ASN (verify), AWS | Vendor-controlled IPs |
| LiteSpeed QUIC.cloud | LiteSpeed-owned netblocks | Some IPs published in docs |
| Perfmatters | Cloudflare Workers (varies) | Edge-based |
| Autoptimize Pro | Site origin (no external crawl) | Local only |
| Smaller / unknown plugin with Vietnam egress | FPT Telecom (AS18403), VNPT (AS45899), Viettel (AS7552), Mobifone (AS131429) | **Matches the WhatsApp lead.** Likely a budget service or a custom-built crawler. |

The Vietnam egress is **unusual** for any of the major Used-CSS vendors. It suggests either:
- The cache plugin in use is a **smaller / regional vendor** with cheap infra (matches "One Man Army"'s phrasing of "cheap mf")
- Or it's a **custom-built crawler** the plugin developer himself runs
- Or the plugin's vendor uses budget VN servers as part of a distributed fleet

This is precisely why we don't allowlist on prior — we verify with Phase C.

---

## 12. If reverse engineering finds something that **isn't** the cache plugin

A few signs the "cache plugin" story is incomplete or wrong:

1. **Path coverage isn't monotonic** — real cache crawlers walk sitemap in order; selective traffic is a scraper
2. **Honeypot anchor is followed** — Used-CSS coverage doesn't click hidden links; that's a credulous scraper
3. **Ad/GA4 endpoints are called every time but assets aren't** — the bot is here for analytics inflation or content scraping, not CSS optimization
4. **JA3 matches known stealth-Puppeteer fingerprints** — cache plugins don't ship with stealth (no reason to evade)
5. **Volume exceeds plausible cache regen budget** — site has N pages; a cache regen visits each ~1×; if you see N×100, it's not just cache work

In any of these cases, the protection plan's full WAF + trust-score + ML stack is needed — the cache-plugin story is at most a partial explanation.

---

*This document is a forensic procedure, not a one-time investigation. Run it for the discovered cache-plugin vendor first. If the same anomalous pattern persists after you allowlist by the verified fingerprint, run it again on the residual — the residual is the real attacker, and now you have the methodology to identify them.*
