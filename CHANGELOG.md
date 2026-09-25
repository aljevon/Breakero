# Changelog

Notable changes land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-09-25

### Added
- Save the report as PDF. A new "pdf" button opens the report in the print
  dialog, where you choose "Save as PDF" (or "Microsoft Print to PDF"). The
  report now carries a proper print stylesheet, so the PDF is a clean, legible
  light-on-white document rather than the dark on-screen theme.
- An upload test image generator for probing Broken Access Control on image
  uploads. It builds a genuinely valid PNG or JPG of about the size you pick
  (~200 KB, ~500 KB, ~1 MB, or under 2 MB) with a unique canary and benign
  access-control probe notes embedded in the file's metadata. Upload it through
  the target's own image field, then check whether the stored file is reachable
  without a session, guessable by id (IDOR), served with its metadata intact, or
  returned to the wrong user. Nothing is uploaded for you; it only writes a local
  file, in keeping with the tool's "you drive the actual request by hand" design.

## [1.7.0] - 2026-09-25

### Changed
- The report you download from the app is now the same premium
  security-assessment document the command line produces: a cover page with an
  overall risk rating and a report reference, an executive summary, a risk
  overview, a navigable findings index, detailed findings with a metadata grid,
  test coverage, methodology and a verification note. It also carries the fixed
  "Contents" dropdown, so a long report is one click from any section instead of
  a scroll. Previously the in-app download used a much plainer layout.

### Fixed
- The report's severity counts and overall risk rating are now derived from the
  findings themselves, so the summary always agrees with the detailed list.
- A report downloaded mid-scan no longer shows a misleading "0.0s" duration; it
  falls back to the live elapsed time until the scan's final total is in.

## [1.6.0] - 2026-09-25

### Added
- The HTML report is now laid out as a proper security-assessment document: a
  cover page with an overall risk rating, an executive summary, a risk overview
  with a severity breakdown, a navigable findings index, and detailed findings
  with a clean metadata grid, evidence, business impact and remediation. It
  reads like an enterprise deliverable and prints sensibly.
- An elegant "Contents" dropdown fixed to the top of the report. It lists every
  section and every finding by id and title, so a long report with many findings
  is one click away from any part instead of a long scroll. Each detailed
  finding also has a "back to top" link.
- Sound in the mini-game: small, playful blips built with the Web Audio API (no
  files, works offline) for flapping, scoring and game over, with a ♪ on/off
  toggle in the game's title bar.

### Changed
- The "play a game while you wait" button is now a filled accent button with a
  gentle wiggle, so it is easier to notice during a long scan.

## [1.5.0] - 2026-09-25

### Added
- A live progress line while a scan runs: percent complete, an estimate of how
  much time is left, and elapsed time, so you are not left guessing how far
  along it is.
- A process panel that shows the scan as it happens, like a terminal: each
  check as it starts and finishes, findings as they land, and the calibration
  step at the top. Faint and monospace so it reads as a log, not a wall of text.
- A small "flappy shield" mini-game to pass the time on a long scan. It slides
  in below the progress line when you ask for it and closes with the × in its
  corner; click or press space to flap. Purely optional and never in the way.

## [1.4.1] - 2026-09-24

### Fixed
- Report download no longer fails with "network issue". The report is now built
  inside the app from data it already has and saved as a file directly, with no
  request to the local server, so a browser that blocks http downloads can't
  break it.

### Added
- A "verify before you trust" note and a references section (OWASP A01,
  PortSwigger access control and IDOR, OWASP WSTG, CWE-284, CWE-639) at the
  bottom of the app and in the HTML report. The note makes clear the results are
  automated leads to confirm by hand, not proof.
- A faint "github.com/aljevon" line at the top of the app window.

## [1.4.0] - 2026-09-24

### Added
- Two new checks, drawn from the PortSwigger Web Security Academy material:
  - `url-bypass`: reaches a blocked path a different way (trailing slash, case,
    encoded slash, dot and semicolon segments like `/admin..;/`, or a rewrite
    header), the classic URL-matching-discrepancy bypass.
  - `param-privilege`: spots access decided by something the client sends, such
    as `?admin=true`, an `X-User-Role: admin` header, or an `isAdmin` cookie.
- forced-browse now also reads robots.txt and sitemap.xml and tries the paths
  the site leaks there. robots.txt in particular often lists admin URLs.
- header-bypass covers more trusted headers, including Referer-based controls
  and True-Client-IP / X-Real-IP.
- A longer built-in list of sensitive paths (swagger, graphql, actuator
  heapdump, phpmyadmin, .env, and more).

## [1.3.2] - 2026-09-24

### Fixed
- Report download no longer fails with "failed to fetch". The keepalive
  watchdog was too aggressive and could shut the local server down during a
  long scan or when the window lost focus; its timeout is now much more lenient.
- Downloads use a direct download link instead of a fetch, so a busy connection
  can't break them.

### Changed
- Reproduction steps are now much more detailed: numbered instructions for
  Windows (open PowerShell, and use curl.exe rather than curl), for Linux and
  macOS, and for the browser, plus what to look for in the reply.
- The native Windows window now has a dark title bar that matches the app
  instead of a white one.
- Brighter, quicker background animation: a livelier scan sweep, a shimmering
  accent rule, and a gently pulsing bolt in the logo.
- Release downloads trimmed to three files (Windows, Linux and macOS, 64-bit)
  so the download page is not confusing. No more arm64 builds, archives or
  checksums.

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

[1.8.0]: https://github.com/aljevon/Breakero/releases/tag/v1.8.0
[1.7.0]: https://github.com/aljevon/Breakero/releases/tag/v1.7.0
[1.6.0]: https://github.com/aljevon/Breakero/releases/tag/v1.6.0
[1.5.0]: https://github.com/aljevon/Breakero/releases/tag/v1.5.0
[1.4.1]: https://github.com/aljevon/Breakero/releases/tag/v1.4.1
[1.4.0]: https://github.com/aljevon/Breakero/releases/tag/v1.4.0
[1.3.2]: https://github.com/aljevon/Breakero/releases/tag/v1.3.2
[1.3.1]: https://github.com/aljevon/Breakero/releases/tag/v1.3.1
[1.3.0]: https://github.com/aljevon/Breakero/releases/tag/v1.3.0
[1.2.0]: https://github.com/aljevon/Breakero/releases/tag/v1.2.0
[1.1.1]: https://github.com/aljevon/Breakero/releases/tag/v1.1.1
[1.1.0]: https://github.com/aljevon/Breakero/releases/tag/v1.1.0
[1.0.0]: https://github.com/aljevon/Breakero/releases/tag/v1.0.0
