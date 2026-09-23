# Changelog

All notable changes to Breakero are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-23

First public release.

### Added
- Nine Broken Access Control test modules mapped to OWASP Top 10 2025 — A01:
  `unauth`, `forced-browse`, `privesc`, `idor`, `method-tampering`,
  `header-bypass`, `cors`, `path-traversal`, and `jwt-inspect`.
- Safety controls enforced in code: authorization gate, host scope lock,
  rate limiting, a global request budget, and read-only-by-default methods.
- Soft-404 / catch-all calibration to suppress false positives.
- Reports: colored terminal output, a self-contained HTML report, and JSON.
- Configuration file support for multi-role, endpoint-aware scans (IDOR and
  privilege-escalation testing).
- Cross-platform binaries for Windows, macOS, and Linux (amd64 and arm64).
- All-in-one installers: `install.sh` (macOS/Linux) and `install.ps1` (Windows).
- Unit and integration tests, plus a GitHub Actions build-and-release pipeline.

[1.0.0]: https://github.com/aljevon/Breakero/releases/tag/v1.0.0
