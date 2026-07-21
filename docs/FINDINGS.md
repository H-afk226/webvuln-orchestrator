
## Authenticated scanning (Step 6)

Three authentication mechanisms were implemented and verified:

| Target | Mechanism | Session obtained |
|--------|-----------|------------------|
| Juice Shop | JWT via JSON login | 732-character bearer token |
| DVWA | PHP session + CSRF token | `PHPSESSID`, `security` |
| bWAPP | PHP session | `PHPSESSID`, `security_level` |

### Result: authentication multiplies crawl reach

Wapiti against DVWA, identical configuration, session the only variable:

| Mode | Pages crawled | Findings |
|------|--------------:|---------:|
| Unauthenticated | 3 | 15 |
| Authenticated | 32 | 17 |

**A 10x increase in crawl reach.** Unauthenticated, the scanner reached
the login page and little else. Every one of DVWA's vulnerability pages
sits behind the session boundary.

### Three silent failure modes encountered

Each of these produced a *successful* scan with *plausible* results
that were quietly wrong. None raised an error.

1. **Wapiti's JSON cookie-jar format was silently ignored.** The scan
   reported "authenticated", completed normally, and produced results
   byte-identical to the unauthenticated run. Replacing the jar file
   with an explicit `Cookie:` header fixed it (crawl went 7 -> 44 pages).

2. **The crawler hit `/logout.php` and destroyed its own session.**
   Scanning continued unauthenticated from that point with no
   indication in the output. Session-destroying endpoints must be
   explicitly excluded.

3. **Attack modules ran but found nothing at the default level.**
   At `--level 1` Wapiti attacks form fields but not query-string
   parameters. DVWA's SQL injection is at `?id=1`, so it was crawled
   but never attacked. All 32 vulnerability categories appeared in the
   report with zero entries -- indistinguishable from "target is secure".

**Conclusion:** authenticated scanning cannot be enabled and trusted.
Each stage -- session acquisition, session retention during the crawl,
and attack depth -- fails silently and independently. Verification is
required at every stage, and a controlled unauthenticated/authenticated
comparison is the only reliable way to detect that authentication
actually took effect.

### Known limitation

Wapiti detects DVWA's SQL injection correctly when invoked directly
against the parameterised URL (confirmed: `SQL Injection (DBMS: MariaDB)`
via parameter `id`). The orchestrator's seed-URL handling does not
currently reproduce this, so injection findings appear in manual runs
but not in orchestrated ones. Per-seed focused scanning is implemented
but not yet passing parameters correctly to the sub-runs.
