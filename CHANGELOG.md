# Changelog

Notable changes land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-23

First public release.

### Added
- Nine broken-access-control checks covering OWASP Top 10 2025, category A01:
  `unauth`, `forced-browse`, `privesc`, `idor`, `method-tampering`,
  `header-bypass`, `cors`, `path-traversal`, and `jwt-inspect`.
- Safety built into the code: the authorization gate, the host scope lock,
  a speed limit, a total request cap, and read-only methods by default.
- A soft-404 step that spots catch-all servers and keeps false positives down.
- Three ways to read results: colored terminal output, a single-file HTML
  report, and JSON.
- Config files for bigger scans with multiple roles and named endpoints, which
  is what IDOR and privilege-escalation testing need.
- Binaries for Windows, macOS, and Linux, both amd64 and arm64.
- One-line installers: `install.sh` for macOS and Linux, `install.ps1` for
  Windows.
- Unit and integration tests, plus a GitHub Actions pipeline that builds and
  publishes releases.

[1.0.0]: https://github.com/aljevon/Breakero/releases/tag/v1.0.0
