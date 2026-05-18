#!/usr/bin/env bash
# Refresh wordpress/mu-plugins/published-ip-ranges.php from vendor sources.
# Run weekly via cron. Outputs a PHP array file ready to drop in.
#
# Usage: ./update-bot-ip-ranges.sh > ../mu-plugins/published-ip-ranges.php

set -euo pipefail

fetch_cidrs() {
    local url="$1"
    curl -sS --fail --max-time 20 "$url" \
        | jq -r '.prefixes[]? | (.ipv4Prefix // .ipv6Prefix // empty)' \
        2>/dev/null || true
}

emit_array() {
    local key="$1"; shift
    printf "    '%s' => [\n" "$key"
    for c in "$@"; do printf "        '%s',\n" "$c"; done
    printf "    ],\n"
}

GPTBOT=$(fetch_cidrs https://openai.com/gptbot.json)
SEARCHBOT=$(fetch_cidrs https://openai.com/searchbot.json)
USERBOT=$(fetch_cidrs https://openai.com/chatgpt-user.json)

printf "<?php\n// Auto-generated %s by update-bot-ip-ranges.sh — do not edit manually\nreturn [\n" "$(date -u +%FT%TZ)"
emit_array "GPTBot"        $GPTBOT
emit_array "OAI-SearchBot" $SEARCHBOT
emit_array "ChatGPT-User"  $USERBOT
emit_array "ClaudeBot"
emit_array "Claude-SearchBot"
emit_array "PerplexityBot"
emit_array "anthropic-ai"
printf "];\n"
