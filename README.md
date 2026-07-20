# webvuln-orchestrator

Multi-scanner web vulnerability orchestration platform. Runs several
DAST tools against a containerised lab of deliberately vulnerable web
applications, normalises their heterogeneous output into a common
schema, and correlates findings across tools.

**Status:** in development (Step 4 of 10 complete)

## What it does

- Orchestrates multiple scanners (OWASP ZAP, Nikto, with Nmap, Wapiti,
  sqlmap and testssl.sh to follow) behind one interface
- Normalises every tool's output into a common `Finding` model with
  CWE IDs and OWASP Top 10 2021 categories
- Fingerprints findings so the same vulnerability reported by different
  tools can be deduplicated and cross-tool agreement measured
- Enforces a scope allowlist: targets not explicitly permitted are refused

## Lab targets

| Target | Stack |
|--------|-------|
| OWASP Juice Shop | Node.js / Angular SPA |
| DVWA | PHP / MySQL |
| WebGoat | Java / Spring |
| bWAPP | PHP / MySQL |

All targets bind to `127.0.0.1` only and are never exposed to the network.

## Quick start

```bash
docker compose -f docker-compose.lab.yml up -d   # vulnerable targets
docker compose up -d                             # scanner stack
docker compose exec orchestrator python -m src.cli targets
docker compose exec orchestrator python -m src.cli scan juiceshop
```

## Legal

This tool scans only hosts on its configured allowlist. Scanning systems
you do not own or have written permission to test is illegal in most
jurisdictions.
