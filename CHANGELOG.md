# Changelog

Notable changes land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-09-24

### Changed
- New visual identity that matches the app. The logo, window/file icon, README
  banner and the HTML report all move to the dark monochrome look with a single
  amber accent (white shield, amber bolt). The old purple/indigo styling is gone.
- The README no longer uses decorative emoji in its headings.

## [1.3.0] - 2026-09-24

### Added
- Every finding now includes "how to reproduce": a curl command that works on
  Windows, Linux and macOS, plus a browser step, so you can confirm it by hand
  before reporting. Shown in the app (with a copy button) and in the HTML report.
- A stop button. The Scan button turns into Stop while a scan runs and cancels
  it cleanly; partial results stay on screen.

### Changed
- Redesigned the app interface: a tight monospace, editorial layout with hairline
  borders (no shadows or gradients), a single accent colour, and a subtle
  animated scan background. Findings and their names stream in live during a scan.
- The native Windows window now shows the Breakero icon.

### Fixed
- Report downloads no longer navigate the window to a "no scan yet" page. They
  save the file directly and are enabled only once a scan has results.

## [1.2.0] - 2026-09-24

### Added
- A true native desktop window on Windows, drawn with the WebView2 runtime
  (built in to Windows 10/11). Breakero is now its own process with its own
  window and taskbar entry, no browser involved. If the WebView2 runtime is
  missing it falls back to the app-mode window, and then to the default browser.
  Uses a pure-Go WebView2 binding, so the whole thing is still one exe with no C
  toolchain needed.

## [1.1.1] - 2026-09-24

### Changed
- The app now opens in its own dedicated window (no tabs, no address bar)
  instead of a browser tab. It uses the Chromium engine already on the machine
  in "app mode" (Edge on Windows, Chrome/Chromium/Brave elsewhere) and falls
  back to the default browser when none is found.

## [1.1.0] - 2026-09-23

### Added
- A graphical app. Double-click the binary (or run `breakero -gui`) and Breakero
  opens in your browser: type a URL, confirm you're authorized, hit Scan, and
  findings stream in live with the same plain-language explanations as the
  reports. Every control has a tooltip. It's a tiny local server bound to
  127.0.0.1 with a per-session token, so only the page it opened can drive it.
- The Windows exe now carries the Breakero icon and version details.

### Changed
- Double-clicking the exe opens the app instead of a console window. On Windows
  the console is hidden; on macOS and Linux running the binary with no arguments
  does the same. The command line is unchanged and still drives the same engine.
- Removed the earlier self-install-to-PATH behavior. Nothing gets copied to
  hidden folders anymore; you just run the binary.

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

[1.3.1]: https://github.com/aljevon/Breakero/releases/tag/v1.3.1
[1.3.0]: https://github.com/aljevon/Breakero/releases/tag/v1.3.0
[1.2.0]: https://github.com/aljevon/Breakero/releases/tag/v1.2.0
[1.1.1]: https://github.com/aljevon/Breakero/releases/tag/v1.1.1
[1.1.0]: https://github.com/aljevon/Breakero/releases/tag/v1.1.0
[1.0.0]: https://github.com/aljevon/Breakero/releases/tag/v1.0.0
