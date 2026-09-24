## Breakero v1.1.1

Small but nice: the app now opens in its **own window**. No tabs, no address bar, no browser chrome around it. Just Breakero.

Before, it opened in a browser tab and you saw a localhost address, which felt like a website. Now double-clicking the exe gives you a proper standalone app window that looks like the tool it is.

How it works: Breakero uses the Chromium engine that's already on your machine in "app mode" (Edge comes with Windows 10 and 11, so there's nothing to install). On macOS and Linux it uses Chrome, Chromium or Brave if you have one. If it can't find any of them, it falls back to opening your default browser, so it still works no matter what.

Everything else is the same as v1.1.0: type a URL, confirm you're authorized, scan, watch findings come in live, download an HTML or JSON report. Same engine and safety rails as the command line.

### What's in the download

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions.
- `checksums.txt` to verify what you grabbed.

Grab a binary below and run it. Please only use it on things you're allowed to test. See AUTHORIZATION.md.
