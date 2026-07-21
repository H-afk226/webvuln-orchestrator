# webvuln-orchestrator

Runs six DAST tools against a containerised lab of deliberately vulnerable
web applications, normalises their output into a common schema, and
correlates findings across tools to measure what each one actually
contributes.

Built to answer a question the tools' own output can't: **how much of
what a vulnerability scanner reports is real, distinct, and unique to
that tool?**

## Headline results

Six scanners against OWASP Juice Shop:

| Metric | Value |
|--------|------:|
| Raw findings | 592 |
| Unique after deduplication | 161 |
| **Duplication** | **73%** |
| Findings corroborated by more than one tool | 1 |

**73% of what six scanners report is redundant.** ZAP alone produced 511
of the 592 raw findings; its passive scanner emits one alert per URL per
rule, so a single missing security header across 83 pages appears as 83
findings. Raw finding counts measure output volume, not detection breadth.

### OWASP Top 10 coverage

| Category | Unique | Detected by |
|----------|-------:|-------------|
| A01 Broken Access Control | 76 | nikto, zap |
| A05 Security Misconfiguration | 3 | nikto, zap, wapiti |
| A06 Vulnerable and Outdated Components | 1 | zap |
| A03 Injection | 1 | **sqlmap only** |

Four of ten categories. The single injection finding came from a
specialist tool given an explicit seed URL — no scanner found it by
crawling.

## Three limitations, measured

These are the project's substantive findings. Each was measured, not
assumed.

### 1. Crawl reach, not detection capability, is the bottleneck

Crawling from the homepage, all six scanners found **zero** injection
vulnerabilities against Juice Shop. Given the endpoint directly, sqlmap
confirmed boolean-based blind SQL injection and fingerprinted the
backend as SQLite in 45 seconds.

The vulnerability was always there. The scanners could not reach it —
on a single-page application, routes are constructed by JavaScript and
are invisible to link-following crawlers.

### 2. Unauthenticated scanning of an authenticated app measures nothing

Wapiti against DVWA, identical configuration, session the only variable:

| Mode | Pages crawled |
|------|--------------:|
| Unauthenticated | 3 |
| Authenticated | 32 |

**A 10x difference in reach.** Every DVWA vulnerability page sits behind
the login boundary.

Three *silent* failure modes were encountered getting there — each
produced a successful scan with plausible results that were quietly
wrong:

- Wapiti's JSON cookie-jar format was silently ignored; the scan
  reported "authenticated" and returned results identical to the
  unauthenticated run
- The crawler hit `/logout.php` and destroyed its own session, then
  continued scanning logged out with no indication
- At the default attack level, query-string parameters are not attacked;
  all 32 vulnerability categories appeared in the report with zero
  entries, indistinguishable from "target is secure"

### 3. DOM-based XSS is structurally undetectable by response-based DAST

Juice Shop's best-known XSS is in the product search. No scanner
detected it. Requesting the endpoint with a script payload returns
`{"status":"success","data":[]}` — the payload is never reflected in the
response, because the Angular frontend writes it into the DOM
client-side. Wapiti's XSS module, run with the exact invocation that
successfully found SQL injection on DVWA, reported nothing.

Every tool here reasons about HTTP request/response pairs. Client-side
vulnerabilities exist only in rendered browser state.

## Architecture

Every scanner implements one abstract interface. Adding a tool costs one
file and one registry entry — the CLI, correlation engine, and reporting
layer never change, because they only ever see `ScanResult` objects.

| Module | Responsibility |
|--------|----------------|
| `config/targets.yml` | scope allowlist, base URLs, credentials, seed URLs |
| `src/cli.py` | scan / report / gate / reparse commands |
| `src/auth.py` | form and JWT session acquisition |
| `src/scanners/base.py` | abstract Scanner interface |
| `src/scanners/*.py` | zap, nikto, nmap, wapiti, sqlmap, testssl |
| `src/schema.py` | Finding, ScanResult, fingerprinting |
| `src/correlate.py` | deduplication, cross-tool agreement |
| `src/report/` | HTML report generation |

### Fingerprinting

Findings are deduplicated by a hash of **CWE + normalised URL + parameter
+ method**, deliberately excluding the tool name, so two scanners
reporting the same vulnerability collide.

Site-wide issues (missing headers, cookie flags, CORS) use a coarser
location-insensitive fingerprint: two tools reporting the same missing
header at different paths have found the same issue.

> **Caveat:** which CWEs count as "site-wide" is a judgment call that
> directly moves the duplication figure. Collapsing CWE-264 across 20
> static assets is defensible; collapsing 70 distinct exposed backup
> files under CWE-530 is more debatable. The list is in
> `src/schema.py:SITEWIDE_CWES`.

### Safety by design

- **Scope allowlist.** Targets not explicitly permitted are refused.
  `check google.com` exits with an error, not a scan.
- **Loopback-only binding.** Vulnerable apps bind to `127.0.0.1`, never
  `0.0.0.0` — Docker's iptables NAT would otherwise expose them to the
  local network.
- **Unprivileged container.** Nmap uses connect scans (`-sT`) rather
  than SYN scans, avoiding `NET_RAW`/`NET_ADMIN`.
- **Detection, not exploitation.** sqlmap runs `--risk 1` without
  `--dump`.

### Raw output preservation

Every scanner's native output is stored alongside normalised findings.
When a parser bug was found after scanning, 13 stored runs were
re-parsed in under a second — re-scanning would have taken over an hour
of tool runtime.

## Lab

| Target | Stack | Why |
|--------|-------|-----|
| OWASP Juice Shop | Node.js / Angular SPA | modern client-rendered app |
| DVWA | PHP / MySQL | server-rendered, authenticated |
| WebGoat | Java / Spring | serves from `/WebGoat`, not root |
| bWAPP | PHP / MySQL | broad vulnerability coverage |

Four stacks chosen deliberately: scanners behave very differently across
them, and that difference is the point.

## Tool versions

Pinned for reproducibility — a scanner comparison without stated
versions is not repeatable.

| Tool | Version | Source |
|------|---------|--------|
| OWASP ZAP | 2.17.0 | official image, driven via REST API |
| Nmap | 7.93 | Debian apt |
| Nikto | 2.5.0 | upstream Git, tag `2.5.0` |
| sqlmap | 1.7.2 | Debian apt |
| Wapiti | 3.2.3 | pip |
| testssl.sh | 3.2.4 | upstream Git, tag `v3.2.4` |

## Quick start

Start the vulnerable targets, then the scanner stack:

    docker compose -f docker-compose.lab.yml up -d
    docker compose up -d

Then list targets, scan, and report:

    docker compose exec orchestrator python -m src.cli targets
    docker compose exec orchestrator python -m src.cli scan juiceshop
    docker compose exec orchestrator python -m src.cli report juiceshop

DVWA and bWAPP need one-time initialisation via their setup pages
(`:8081` and `:8083/install.php`).

### Commands

| Command | Purpose |
|---------|---------|
| `targets` | list configured targets and scope status |
| `check <target>` | verify scope without scanning |
| `scan <target> [--tools ...] [--no-auth]` | run scanners |
| `report <target>` | correlate and render HTML |
| `reparse <target>` | re-parse stored raw output with current parsers |
| `gate <target> [--update]` | fail on new high-severity findings (CI) |

## Integration notes

Problems that only appear when wiring six independently-maintained tools
into one image:

- Nikto is not packaged in Debian (only Kali) — installed from upstream
- Nikto's JSON report plugin fails with a Perl module resolution error
  even with `libjson-perl` present — CSV output used instead
- ZAP 2.17 returns string risk labels, not the numeric `riskcode` of
  older API versions; the parser silently defaulted all 511 findings to
  *informational* until raw output was inspected
- `wapiti3` downgrades `typing_extensions`, breaking pydantic v2
- testssl.sh has no fast-fail path for non-TLS endpoints — it exhausts
  its full probe battery via timeouts (~20 min to discover there is no
  TLS); an applicability check was added
- Concurrent scanning destabilised DVWA; scans against one target must
  be serialised

Full detail in `docs/FINDINGS.md`.

## Known limitations

- Wapiti detects DVWA's SQL injection when invoked directly against the
  parameterised URL, but the orchestrator's per-seed sub-runs do not yet
  reproduce this
- No browser-driven scanning, so DOM-based vulnerabilities are out of
  reach by design
- The CWE to OWASP map covers the CWEs these tools emit, not all of
  them; roughly half of ZAP's findings carry no CWE at all, placing a
  ceiling on CWE-based correlation

## Legal

This tool scans only hosts on its configured allowlist. Scanning systems
you do not own or have written permission to test is illegal in most
jurisdictions.
