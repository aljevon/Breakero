## Breakero v1.3.2

Fixes and polish from real‑world use.

### Report download fixed

Saving a report could fail with "could not save the report: failed to fetch", usually after a long scan or when the window lost focus. The cause was the little watchdog that closes the app when its window goes away: it was too quick and could shut the local server down early. It's now far more patient, and downloads go straight to a download link instead of a fetch, so a busy connection can't break them.

### Reproduction steps, spelled out

Every finding's "how to reproduce" is now step by step for someone who has never touched a terminal: how to open PowerShell on Windows (and the important detail that you type `curl.exe`, not `curl`), the same for a terminal on Linux and macOS, the browser way, and what to look at in the reply to know it's real.

### Dark title bar

On Windows the window's title bar is dark now and matches the app, instead of the old white bar. It reads like a proper dark‑mode app.

### Livelier animation

The background scan sweep is brighter and quicker, the accent line shimmers, and the bolt in the logo gives a gentle pulse.

### What's in the download

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions.
- `checksums.txt` to verify what you grabbed.

Grab a binary below and run it. Please only use it on things you're allowed to test. See AUTHORIZATION.md.
