## Breakero v1.3.0

New look and a few things you asked for.

### Reproduce every finding by hand

Each finding now comes with a "how to reproduce" block: a curl command that works the same on Windows, Linux and macOS, plus a browser step. So you can cross-check anything the scanner reports before you write it up. It's in the app (with a copy button) and in the HTML report.

### Stop a scan

The scan button turns into a stop button while a scan is running. Hit it and the scan cancels straight away; whatever it already found stays on screen.

### Redesigned interface

Tighter, more of a tool and less of a website: a monospace editorial layout, hairline borders instead of drop shadows, one accent colour, and a quiet animated scan background. Findings and their names now show up live as the scan runs, not just at the end.

### Fixes

- The Windows app window now shows the Breakero icon.
- Downloading a report used to navigate to a blank "no scan yet" page you couldn't get back from. Now it saves the file directly, and the buttons only light up once there's something to save.

Everything else is unchanged: native window on Windows (WebView2), app-mode window on macOS and Linux, same engine and safety rails.

### What's in the download

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions.
- `checksums.txt` to verify what you grabbed.

Grab a binary below and run it. Please only use it on things you're allowed to test. See AUTHORIZATION.md.
