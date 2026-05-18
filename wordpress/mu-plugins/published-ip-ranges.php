<?php
/*
Vendor-published IP ranges for bots that do NOT support reverse DNS.
Refresh weekly via wordpress/scripts/update-bot-ip-ranges.sh.

Keys must match (or be a substring of) the User-Agent token in fw_bot_manifest().
Sources:
  - OpenAI:    https://openai.com/gptbot.json
               https://openai.com/searchbot.json
               https://openai.com/chatgpt-user.json
  - Anthropic: https://docs.anthropic.com/.../crawler-ips  (verify current location)
  - Perplexity: https://docs.perplexity.ai/...             (not consistently published)
  - Bytespider: ByteDance publishes via robots/IP doc page; verify periodically.

Last updated: <DATE>   (UPDATE WHEN YOU REFRESH)
*/
return [
    'GPTBot' => [
        // 'a.b.c.d/24',
    ],
    'OAI-SearchBot' => [
        // 'a.b.c.d/24',
    ],
    'ChatGPT-User' => [
        // 'a.b.c.d/24',
    ],
    'ClaudeBot' => [
        // 'a.b.c.d/24',
    ],
    'Claude-SearchBot' => [
        // 'a.b.c.d/24',
    ],
    'PerplexityBot' => [
        // 'a.b.c.d/24',
    ],
    'anthropic-ai' => [
        // 'a.b.c.d/24',
    ],
];
