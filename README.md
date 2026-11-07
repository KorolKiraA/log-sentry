# LogSentry

![Java](https://img.shields.io/badge/Java-17%2B-orange) ![License](https://img.shields.io/badge/license-MIT-blue) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

A mini-SIEM CLI analyzer for Apache/Nginx access logs (combined format).
Turns gigabytes of raw logs into an actionable security & traffic report in
seconds — a free first line of defense before investing in paid SIEM tooling.

## Features

- HTTP status-class breakdown (2xx/3xx/4xx/5xx) with percentages
- Top-5 requested URLs and top-5 client IPs
- Suspicious-IP detection (error rate > 50% — brute force, scanners)
- Per-hour traffic histogram rendered in the terminal
- Built-in demo log for instant evaluation

## Quick start

Requires **JDK 17+**:

```bash
java LogSentry.java /var/log/nginx/access.log   # your log
java LogSentry.java                              # built-in demo log
```

## Sample output

```
--- Suspicious IPs (4xx/5xx share > 50%) ---
  ⚠ 203.0.113.77: 5 requests, 5 errors (100%)

--- Requests per hour ---
  10:00 | ████████████████████████████████████████ 5
  12:00 | ████████████████ 2
```

## Tech stack

Java 17 · Stream API · regex · records · standard library only.

## License

MIT — see [LICENSE](LICENSE).
