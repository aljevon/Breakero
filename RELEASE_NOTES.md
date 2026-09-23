## Breakero v1.1.0

Big one: Breakero has an app now. Double-click it and it opens in your browser. No console, no install, no digging through folders.

### The app

Type a target URL, tick the box that says you're allowed to test it, hit Scan. Findings come in as you watch, each one written in plain language with the evidence and how to fix it. Hover any button or field and a little tooltip tells you what it does. When you're done you can pull down an HTML or JSON report.

Under the hood it's a small web server bound to your own machine (127.0.0.1) with a random per-session token, so nothing else can reach it. Same scanning engine as the command line, same safety rails: it won't run until you confirm you're authorized, it only touches the host you typed, and it's rate limited.

It works the same way on Windows, macOS and Linux. Just run the binary, or `breakero -gui`.

### Also in this release

- The Windows exe carries the Breakero icon and proper version details.
- Double-clicking no longer pops a console window or copies anything to hidden folders. It just opens the app.
- The command line is untouched. Everything from v1.0.0 still works.

### The checks (unchanged)

unauth, forced-browse, privesc, idor, method-tampering, header-bypass, cors, path-traversal, jwt-inspect. All mapped to OWASP Top 10 2025, category A01.

### What's in the download

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions.
- `checksums.txt` to verify what you grabbed.

Grab a binary below and run it. Please only use it on things you're allowed to test. See AUTHORIZATION.md.
