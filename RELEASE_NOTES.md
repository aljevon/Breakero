## Breakero v1.0.0

First release. It's a small command-line scanner for broken access control, which is the top item on the OWASP Top 10 for 2025 (category A01). One binary, no dependencies, runs on Windows, macOS and Linux.

### What it can do

Nine checks, each aimed at a real access-control mistake:

- **unauth** finds pages and APIs that serve real content with nobody logged in.
- **forced-browse** guesses the addresses of things that should be hidden, like admin panels, config, `.git` and actuator endpoints.
- **privesc** checks whether a low-privilege account can reach admin-only features.
- **idor** swaps object ids to see if you can read someone else's data (IDOR / BOLA).
- **method-tampering** tries other HTTP verbs when GET is blocked, in case one slipped through.
- **header-bypass** replays known trust headers like `X-Forwarded-For` and `X-Original-URL` to get past a block.
- **cors** flags a CORS setup that reflects any origin and allows credentials.
- **path-traversal** looks for file reads outside the intended folder. Detection only, it doesn't pull files down.
- **jwt-inspect** decodes the tokens you give it and points out weak ones: `alg=none`, no expiry, a role claim the client could edit.

### The safety side

It won't run until you confirm you're allowed to test the target, and it refuses to touch any host outside your scope. Requests are paced and capped, and it stays read-only unless you turn on `-active`. There's also a soft-404 step that notices catch-all servers so you don't drown in false positives.

### Reports

Color in the terminal, a single self-contained HTML file you can send to someone, and JSON if you want to script around it. Every finding comes with a plain-language explanation, the evidence, and how to fix it.

### What's in this release

- Binaries for Windows, macOS and Linux (amd64 and arm64), plus zipped and tarred versions of each.
- `install.sh` for macOS and Linux, `install.ps1` for Windows.
- `checksums.txt` so you can verify what you downloaded.

Grab a binary below, or use the one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/aljevon/Breakero/breakero/install.sh | sh
```

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
