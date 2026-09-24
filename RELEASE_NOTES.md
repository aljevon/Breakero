## Breakero v1.2.0

Windows now gets a full native desktop app. Double-click `breakero-windows-amd64.exe` and it opens as its own window, its own process, its own taskbar entry. No browser, nothing wrapped around it. Just Breakero.

It's drawn with WebView2, the engine that already comes with Windows 10 and 11, so there's nothing extra to install. If for some reason the WebView2 runtime isn't there, it quietly falls back to an app-mode window, and then to your default browser, so it always opens.

The nice part: it's still a single exe with no C toolchain or extra DLLs to ship. macOS and Linux keep the dedicated app-mode window (Chrome, Chromium, Edge or Brave).

Everything else is the same: type a URL, confirm you're authorized, scan, watch findings stream in, pull down an HTML or JSON report. Same engine and safety rails as the command line.

### What's in the download

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions.
- `checksums.txt` to verify what you grabbed.

Grab a binary below and run it. Please only use it on things you're allowed to test. See AUTHORIZATION.md.
