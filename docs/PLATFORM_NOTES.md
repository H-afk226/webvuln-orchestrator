# Platform Notes

## Kali Linux (native Docker) — baseline

### Initial image pull (cold cache)
| Image | Time (s) |
|-------|---------:|
| vulnerables/web-dvwa | 566 |
| webgoat/webgoat | 744 |
| raesene/bwapp | 305 |
| bkimminich/juice-shop | (cached) |

### Target readiness
| Target | Host port | Root path | Notes |
|--------|-----------|-----------|-------|
| Juice Shop | 3000 | `/` -> 200 | ready immediately |
| DVWA | 8081 | `/` -> 302 setup.php | requires DB init |
| WebGoat | 8082 | `/` -> 404, `/WebGoat/login` -> 200 | healthcheck reports unhealthy but app is functional |
| bWAPP | 8083 | `/` -> 302 | requires install.php |

**Finding:** not all targets serve from the web root. Scanners aimed at `/`
under-report on WebGoat, which serves from `/WebGoat`. Per-target base paths
are therefore required configuration, not an optional convenience.

### Environment
- All target ports bound to `127.0.0.1` only, preventing LAN exposure of
  intentionally vulnerable applications.
- Shared user-defined bridge network `vulnlab` provides container DNS,
  so targets are addressed by service name rather than IP.
