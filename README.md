<div align="center">

<img src="assets/banner.png" alt="Breakero — Broken Access Control Scanner" width="100%">

<p><em>A fast, friendly scanner for <strong>Broken Access Control</strong> — the #1 risk in the OWASP Top 10 (2025), category A01.</em></p>

<p>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/get%20started-in%2060%20seconds-6366f1?style=for-the-badge" alt="Get started"></a>
  <a href="AUTHORIZATION.md"><img src="https://img.shields.io/badge/use-authorized%20testing%20only-c026d3?style=for-the-badge" alt="Authorized use only"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go 1.24+">
  <img src="https://img.shields.io/badge/platforms-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-2a2e3a" alt="Platforms">
  <img src="https://img.shields.io/badge/dependencies-zero-3fb950" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license">
  <img src="https://img.shields.io/badge/OWASP-A01%3A2025-e11d48" alt="OWASP A01:2025">
</p>

</div>

---

Breakero is a single-binary command-line tool that checks a web app or API for
**Broken Access Control** — cases where the application lets someone see or do
something they should not be allowed to. Think opening an admin page without
logging in, reading another user's data by changing an `id` in the URL, or
deleting a record through an HTTP method nobody remembered to lock down.

It is built to be **approachable**. If you are just starting out on a Red Team
or in a SOC, Breakero explains every finding in plain language: what it means,
the evidence it saw, and how a developer fixes it. If you are experienced, it
gets out of your way and gives you clean JSON to pipe into the rest of your
workflow.

> [!IMPORTANT]
> **Only run Breakero against systems you own or are explicitly authorized to
> test.** Testing without written permission is illegal in most countries.
> Breakero refuses to start until you confirm authorization, and it will never
> touch a host outside the scope you define. Please read
> [`AUTHORIZATION.md`](AUTHORIZATION.md) first.

---

## Contents

- [Why Breakero](#-why-breakero)
- [Safety by design](#-safety-by-design)
- [Install](#-install)
- [Quick start](#-quick-start)
- [What it tests](#-what-it-tests)
- [Sample report](#-sample-report)
- [Configuration](#-configuration)
- [Command-line options](#-command-line-options)
- [Understanding the results](#-understanding-the-results)
- [Practice legally](#-practice-legally)
- [Build from source](#-build-from-source)
- [Project layout](#-project-layout)
- [License](#-license)

---

## ✨ Why Breakero

- **One file, no setup.** No Python, no Node, no libraries to install. Download
  the binary (or the `.exe`), run it. Cold start is instant.
- **Made for learning.** `breakero -explain` walks you through every test in
  everyday language. The HTML report opens with a short "read me first" primer.
- **Safe out of the box.** Rate limiting, a request budget, a hard scope lock,
  and read-only defaults mean you can explore without breaking things.
- **Reports you can hand to anyone.** Colorful terminal output, a polished
  self-contained HTML report, and machine-readable JSON.
- **Fewer false alarms.** Automatic soft-404 / catch-all calibration filters
  out the noise that makes most path scanners frustrating.

## 🛡 Safety by design

These are enforced by the code, not just written in a doc:

| Control | What it does |
|---|---|
| **Authorization gate** | Won't start unless you pass `-i-am-authorized` (or set `authorized: true`). Your attestation that you have permission. |
| **Scope lock** | Every request is checked against your in-scope hosts. Anything else — even a redirect that leaves scope — is refused and never sent. |
| **Rate limiting** | Requests are paced (default 5/sec). Breakero is a tester, not a stress tool, and is built so it can't be used as one by accident. |
| **Request budget** | A global cap (default 2000) keeps any run bounded. |
| **Read-only by default** | State-changing methods (POST/PUT/PATCH/DELETE) are off unless you explicitly pass `-active`. |

## 📦 Install

### Option A — Download a ready-to-run binary

Grab the file for your system from the [**Releases**](../../releases) page:

| System | File |
|---|---|
| Windows 64-bit | `breakero-windows-amd64.exe` |
| Windows ARM | `breakero-windows-arm64.exe` |
| Linux 64-bit | `breakero-linux-amd64` |
| Linux ARM64 | `breakero-linux-arm64` |
| macOS (Intel) | `breakero-darwin-amd64` |
| macOS (Apple Silicon) | `breakero-darwin-arm64` |

On **Windows**, open PowerShell in the download folder and run:

```powershell
.\breakero-windows-amd64.exe -version
```

On **Linux / macOS**, make it executable first:

```bash
chmod +x breakero-linux-amd64
./breakero-linux-amd64 -version
```

### Option B — One-line installer (macOS & Linux)

An all-in-one installer detects your OS and architecture, downloads the latest
release, and installs `breakero` onto your `PATH`:

```bash
curl -fsSL https://raw.githubusercontent.com/aljevon/Breakero/breakero/install.sh | bash
```

Prefer to read before you run? Download [`install.sh`](install.sh), review it,
then execute it. On **Windows**, use the PowerShell installer:

```powershell
irm https://raw.githubusercontent.com/aljevon/Breakero/breakero/install.ps1 | iex
```

### Option C — Build it yourself

See [Build from source](#-build-from-source). You only need Go 1.24+.

## 🚀 Quick start

Run a basic scan. The `-i-am-authorized` flag is your confirmation that you have
permission to test the target:

```bash
breakero -url https://your-target.example -i-am-authorized -html report.html
```

Learn what each test does (great when you're starting out):

```bash
breakero -explain
```

Scan as a logged-in user, to test access between accounts:

```bash
breakero -url https://your-target.example -i-am-authorized \
  -cookie "session=YOUR_SESSION_COOKIE"
```

Run a deep scan with multiple roles and endpoints, driven by a config file:

```bash
breakero -config configs/example.json
```

## 🔍 What it tests

Every module maps to a real Broken Access Control pattern from OWASP A01:2025.
Run `breakero -list-checks` for the ids, or `-explain` for the plain-language
version.

| Module (`id`) | What it looks for |
|---|---|
| `unauth` | Endpoints that serve protected content with no login (missing authentication) |
| `forced-browse` | Guessing the address of sensitive pages — admin panels, config, `.git`, actuator |
| `privesc` | Vertical privilege escalation: a low-privilege role reaching admin-only features |
| `idor` | IDOR / BOLA: reading another user's object by swapping the `id` |
| `method-tampering` | HTTP verb tampering — a rule that guards GET but forgets HEAD/PUT/DELETE |
| `header-bypass` | Bypassing a denial with a trusted header (`X-Forwarded-For`, `X-Original-URL`, …) |
| `cors` | CORS misconfiguration that reflects any origin together with credentials |
| `path-traversal` | Reading files outside the intended folder (`../../etc/passwd`), detection-only |
| `jwt-inspect` | Token / JWT weaknesses: `alg=none`, no expiry, privilege claims held client-side |

Every module goes through one shared HTTP client that **enforces scope, rate
limiting, and the request budget** — no module can slip past those controls.

## 🖼 Sample report

The HTML report is self-contained — one file, no external assets — so you can
open it anywhere or attach it to a ticket. Every finding is explained in plain
language with the evidence and a fix.

<div align="center">
  <img src="assets/report-sample.png" alt="Breakero HTML report" width="780">
</div>

## ⚙️ Configuration

To detect **IDOR** and **privilege escalation**, Breakero needs to know which
role holds which credentials, and which objects belong to whom. A full example
lives in [`configs/example.json`](configs/example.json). In short:

```json
{
  "authorized": true,
  "base_url": "https://app.example.com",
  "scope_include": ["app.example.com", "*.api.example.com"],
  "rate_per_second": 5,
  "max_requests": 3000,
  "roles": [
    { "name": "anonymous", "level": 0 },
    { "name": "alice", "level": 10, "cookie": "session=...", "owned_ids": ["1001"] },
    { "name": "bob",   "level": 10, "cookie": "session=...", "owned_ids": ["1002"] },
    { "name": "admin", "level": 100, "cookie": "session=..." }
  ],
  "endpoints": [
    { "path": "/admin",          "method": "GET", "min_role": "admin", "sensitive": true },
    { "path": "/api/v1/account", "method": "GET", "min_role": "alice", "id_param": "id" },
    { "path": "/download",       "method": "GET", "id_param": "file" }
  ]
}
```

- **`level`** — privilege level; higher is more privileged, `0` is anonymous.
- **`owned_ids`** — object ids that legitimately belong to a role; used to test
  cross-user access (BOLA).
- **`id_param`** — the parameter that holds an object reference (for IDOR), or
  use a `{id}` placeholder in the path. A param named like `file`/`path` also
  feeds the path-traversal module.
- **`min_role`** — the least-privileged role that should be allowed; used by the
  privilege-escalation module.

## 🎛 Command-line options

| Flag | Meaning |
|---|---|
| `-url` | Target base URL |
| `-i-am-authorized` | **Required.** Confirms you have permission to test |
| `-config` | Path to a JSON config file |
| `-cookie` | Cookie for a quick authenticated scan |
| `-header` | Extra header `Name: Value` (separate several with `;;`) |
| `-checks` | Limit to specific modules, e.g. `unauth,cors` |
| `-scope` / `-exclude` | Add / remove in-scope hosts (supports `*.example.com`) |
| `-rate` | Requests per second (default 5) |
| `-max-requests` | Global request budget (default 2000) |
| `-active` | Allow state-changing methods (POST/PUT/PATCH/DELETE) — use with care |
| `-html` / `-json` | Write a report to a file |
| `-explain` | Explain each module (learning mode) |
| `-list-checks` | List the modules |

Run `breakero -h` for the complete list.

## 📊 Understanding the results

Each finding has a **severity** (CRITICAL → INFO) and a **confidence**:

- `confirmed` — proven (e.g. a path-traversal payload that returned file contents).
- `likely` — strongly supported by comparison.
- `needs-review` — verify it by hand. Automated tools can be fooled by unusual
  apps, so always confirm before you report.

Breakero also runs a **soft-404 calibration**: if the server answers `200 OK`
with content for pages that don't exist (a catch-all), Breakero notices and
stops flagging every guessed path — which cuts false positives dramatically.

> "No findings" is **not** a certificate of security. It means these specific
> tests didn't trigger. Breakero is a strong starting point, not a replacement
> for manual testing and business-logic review.

## 🎯 Practice legally

No target you're allowed to test yet? Practice on intentionally vulnerable apps
you run yourself:

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [DVWA — Damn Vulnerable Web Application](https://github.com/digininja/DVWA)

## 🧱 Build from source

You only need [Go 1.24+](https://go.dev/dl/).

```bash
# Linux / macOS — build every platform's binary into ./dist
./build.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\build.ps1

# or with make
make release      # all platforms
make build        # just your current OS
make test         # run the test suite
```

## 🗂 Project layout

```
cmd/breakero        CLI entry point
internal/checks     the A01 test modules
internal/httpx      HTTP client with scope + rate limit + budget
internal/scope      host-boundary enforcement (safety)
internal/engine     orchestration + soft-404 calibration
internal/report     terminal / HTML / JSON reports
internal/config     configuration + the authorization gate
internal/finding    finding model + severity
```

## 📄 License

Released under the [MIT License](LICENSE). Use it responsibly and legally.

<div align="center"><sub>Breakero · Broken Access Control Scanner · OWASP Top 10 2025 — A01</sub></div>
