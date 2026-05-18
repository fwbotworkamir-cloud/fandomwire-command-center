<?php
/*
Cache-plugin Puppeteer fleet egress CIDRs.
POPULATE after running docs/reverse-engineer-crawler.md §C and confirming with "One Man Army".
DO NOT add CIDRs you have not personally verified — false allowlisting is worse than no allowlisting.
*/
return [
    // '203.0.113.0/24',          // example: FPT Telecom block
    // '14.241.0.0/16',           // example: VNPT block
    // '171.244.0.0/16',          // example: Viettel block
    // '<single-ip>',             // also valid: bare IP, treated as /32
];
