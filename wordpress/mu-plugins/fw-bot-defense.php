<?php
/*
Plugin Name: FW Bot Defense
Description: Two-layer bot defense — cache-crawler tagging (suppress GA4 + ads) + reverse-DNS verification of declared bot UAs (block spoofers).
Version:     1.0.0
Author:      FandomWire Security

DEPLOY AS:   wp-content/mu-plugins/fw-bot-defense.php
COMPANION:   wp-content/mu-plugins/cache-crawler-ips.php  (vendor egress CIDRs)
COMPANION:   wp-content/mu-plugins/published-ip-ranges.php (AI vendor IP lists)
*/

if (!defined('ABSPATH')) exit;

const FW_BOT_VERIFY_TTL = 86400;
const FW_BOT_SPOOF_TTL  = 21600;

const FW_CACHE_CRAWLER_UA_TOKENS = ['FlyingPress', 'WP-Rocket-Crawler', 'UsedCSS', 'NitroPack', 'LiteSpeedBot', 'CriticalCSS'];
const FW_CACHE_CRAWLER_HEADER    = 'HTTP_X_CACHE_GEN';
const FW_CACHE_CRAWLER_SECRET    = '';

function fw_cache_crawler_ips() {
    $f = __DIR__ . '/cache-crawler-ips.php';
    return is_readable($f) ? (array) include $f : [];
}

function fw_bot_manifest() {
    return [
        'Googlebot'           => ['.googlebot.com', '.google.com'],
        'Storebot-Google'     => ['.googlebot.com', '.google.com'],
        'AdsBot-Google'       => ['.googlebot.com', '.google.com'],
        'Googlebot-Image'     => ['.googlebot.com', '.google.com'],
        'Googlebot-Video'     => ['.googlebot.com', '.google.com'],
        'Bingbot'             => ['.search.msn.com'],
        'AdIdxBot'            => ['.search.msn.com'],
        'BingPreview'         => ['.search.msn.com'],
        'Applebot'            => ['.applebot.apple.com', '.apple.com'],
        'DuckDuckBot'         => ['.duckduckgo.com'],
        'DuckDuckGo'          => ['.duckduckgo.com'],
        'YandexBot'           => ['.yandex.com', '.yandex.ru', '.yandex.net'],
        'YandexImages'        => ['.yandex.com', '.yandex.ru', '.yandex.net'],
        'Baiduspider'         => ['.crawl.baidu.com', '.crawl.baidu.jp'],
        'facebookexternalhit' => ['.fbsv.net', '.tfbnw.net', '.facebook.com'],
        'meta-externalagent'  => ['.fbsv.net', '.tfbnw.net', '.facebook.com'],
        'Meta-ExternalAgent'  => ['.fbsv.net', '.tfbnw.net', '.facebook.com'],
        'LinkedInBot'         => ['.linkedin.com'],
        'Twitterbot'          => ['.twitter.com', '.twttr.com', '.x.com'],
        'PetalBot'            => ['.aspiegel.com', '.petalsearch.com'],
        'GPTBot'              => null,
        'OAI-SearchBot'       => null,
        'ChatGPT-User'        => null,
        'ClaudeBot'           => null,
        'Claude-SearchBot'    => null,
        'PerplexityBot'       => null,
        'anthropic-ai'        => null,
        'Bytespider'          => null,
    ];
}

function fw_published_ip_ranges() {
    $f = __DIR__ . '/published-ip-ranges.php';
    return is_readable($f) ? (array) include $f : [];
}

add_action('muplugins_loaded', 'fw_bot_defense_dispatch', 0);

function fw_bot_defense_dispatch() {
    $ip = fw_real_ip();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    if (defined('DOING_CRON') || defined('WP_CLI') || str_starts_with($_SERVER['REQUEST_URI'] ?? '/', '/wp-admin')) {
        return;
    }
    if (!$ip || $ua === '') {
        define('FW_TRUST_BAND', 'unknown_ip_or_ua');
        return;
    }

    if (fw_is_cache_crawler($ip, $ua)) {
        define('FW_TRUST_BAND', 'cache_crawler');
        fw_suppress_analytics_and_ads();
        header('X-FW-Trust: cache_crawler');
        return;
    }

    if (preg_match('~HeadlessChrome|Puppeteer\b|Playwright\b|phantomjs|Electron/[\d.]+|\bSelenium\b~i', $ua)) {
        fw_403('signature_block');
    }

    $claim = fw_match_bot_claim($ua);
    if ($claim !== null) {
        $v = fw_verify_bot($ip, $claim);
        if ($v === true)  { define('FW_TRUST_BAND', 'verified_bot');   header('X-FW-Trust: verified:' . $claim); return; }
        if ($v === false) { fw_403('spoof:' . $claim); }
        define('FW_TRUST_BAND', 'unverified_bot_claim:' . $claim);
        fw_suppress_analytics_and_ads();
        header('X-FW-Trust: unverified:' . $claim);
        return;
    }

    $is_https = !empty($_SERVER['HTTPS']) || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    if (stripos($ua, 'Chrome/') !== false && $is_https && empty($_SERVER['HTTP_SEC_CH_UA'])) {
        define('FW_TRUST_BAND', 'ua_mismatch');
        fw_suppress_analytics_and_ads();
        header('X-FW-Trust: ua_mismatch');
        return;
    }

    define('FW_TRUST_BAND', 'trusted');
}

function fw_real_ip() {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $h) {
        $v = $_SERVER[$h] ?? '';
        if ($v === '') continue;
        $first = trim(explode(',', $v)[0]);
        if (filter_var($first, FILTER_VALIDATE_IP)) return $first;
    }
    return null;
}

function fw_is_cache_crawler($ip, $ua) {
    if (FW_CACHE_CRAWLER_SECRET !== '' &&
        hash_equals(FW_CACHE_CRAWLER_SECRET, $_SERVER[FW_CACHE_CRAWLER_HEADER] ?? '')) {
        return true;
    }
    foreach (FW_CACHE_CRAWLER_UA_TOKENS as $t) {
        if ($t !== '' && stripos($ua, $t) !== false) return true;
    }
    foreach (fw_cache_crawler_ips() as $cidr) {
        if (fw_ip_in_cidr($ip, $cidr)) return true;
    }
    return false;
}

function fw_match_bot_claim($ua) {
    foreach (array_keys(fw_bot_manifest()) as $token) {
        if (stripos($ua, $token) !== false) return $token;
    }
    return null;
}

function fw_verify_bot($ip, $bot_token) {
    $key = 'fw_bot_v_' . md5($ip . '|' . $bot_token);
    $cached = get_transient($key);
    if ($cached !== false) {
        if ($cached === 'verified') return true;
        if ($cached === 'spoof')    return false;
        return null;
    }

    $manifest = fw_bot_manifest();
    $expected = array_key_exists($bot_token, $manifest) ? $manifest[$bot_token] : null;

    if (is_array($expected)) {
        $ptr = @gethostbyaddr($ip);
        if (!$ptr || $ptr === $ip) {
            set_transient($key, 'spoof', FW_BOT_SPOOF_TTL);
            return false;
        }
        $ptr_l = strtolower($ptr);
        $match = false;
        foreach ($expected as $suffix) {
            if (str_ends_with($ptr_l, strtolower($suffix))) { $match = true; break; }
        }
        if (!$match) {
            set_transient($key, 'spoof', FW_BOT_SPOOF_TTL);
            return false;
        }
        $forward = @gethostbyname($ptr);
        $ok = ($forward === $ip);
        set_transient($key, $ok ? 'verified' : 'spoof', $ok ? FW_BOT_VERIFY_TTL : FW_BOT_SPOOF_TTL);
        return $ok;
    }

    foreach (fw_published_ip_ranges() as $vendor_token => $cidrs) {
        if (stripos($bot_token, $vendor_token) === false &&
            stripos($vendor_token, $bot_token) === false) continue;
        foreach ((array)$cidrs as $cidr) {
            if (fw_ip_in_cidr($ip, $cidr)) {
                set_transient($key, 'verified', FW_BOT_VERIFY_TTL);
                return true;
            }
        }
        set_transient($key, 'spoof', FW_BOT_SPOOF_TTL);
        return false;
    }

    set_transient($key, 'unknown', FW_BOT_SPOOF_TTL);
    return null;
}

function fw_ip_in_cidr($ip, $cidr) {
    if (!is_string($cidr) || $cidr === '') return false;
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if ($bits < 0 || $bits > 32) return false;
        $mask = $bits === 0 ? 0 : (~((1 << (32 - $bits)) - 1)) & 0xFFFFFFFF;
        return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
    }

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) &&
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if ($bits < 0 || $bits > 128) return false;
        $ipb  = inet_pton($ip);
        $subb = inet_pton($subnet);
        $full = intdiv($bits, 8);
        $rem  = $bits % 8;
        if (substr($ipb, 0, $full) !== substr($subb, 0, $full)) return false;
        if ($rem === 0) return true;
        $mask = chr((0xFF << (8 - $rem)) & 0xFF);
        return (ord($ipb[$full]) & ord($mask)) === (ord($subb[$full]) & ord($mask));
    }
    return false;
}

function fw_suppress_analytics_and_ads() {
    add_action('init', function () {
        global $wp_filter;
        foreach (['wp_head', 'wp_footer', 'wp_body_open'] as $hook) {
            if (empty($wp_filter[$hook])) continue;
            foreach ($wp_filter[$hook]->callbacks as $prio => $cbs) {
                foreach ($cbs as $id => $cb) {
                    if (is_string($id) && preg_match('/gtag|googletagmanager|google_analytics|gtm|analytics|adsense|adsbygoogle/i', $id)) {
                        unset($wp_filter[$hook]->callbacks[$prio][$id]);
                    }
                }
            }
        }
    }, 0);
    add_filter('option_active_plugins', function ($plugins) {
        $strip = [
            'ad-inserter/ad-inserter.php',
            'advanced-ads/advanced-ads.php',
            'wp-quads/wp-quads.php',
            'ezoic-integration/ezoic-integration.php',
            'mediavine-control-panel/mediavine-control-panel.php',
        ];
        return array_values(array_diff((array)$plugins, $strip));
    });
}

function fw_403($reason) {
    status_header(403);
    header('Cache-Control: no-store');
    header('X-FW-Block: ' . $reason);
    echo '403';
    exit;
}
