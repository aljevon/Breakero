## Breakero v1.4.0

Stronger detection. Two new checks and some sharper existing ones, taking cues from the PortSwigger Web Security Academy access-control material.

### New: url-bypass

A blocked path like `/admin` can often be reached a slightly different way, because a proxy or framework matches the URL as text while the app resolves it to the same page. This check tries the classics: a trailing slash, uppercase, an encoded slash, dot and semicolon segments (`/admin/.`, `/admin%2f`, `/admin..;/`), a double slash, and rewrite headers. If any of them gets in where the plain path was blocked, it flags it.

### New: param-privilege

Some apps decide what you can do from something you send them: `?admin=true` in the URL, an `X-User-Role: admin` header, or an `isAdmin` cookie. This check adds those to blocked requests and sees whether they open up. If they do, the app trusted a value you controlled.

### Sharper existing checks

- forced-browse now reads robots.txt and sitemap.xml and tries the paths the site leaks there. robots.txt loves to list the exact admin URLs it wants hidden.
- header-bypass covers more trusted headers, including Referer-based controls and True-Client-IP / X-Real-IP.
- A longer built-in list of sensitive paths (swagger, graphql, actuator heapdump, phpmyadmin, .env and more).

Same safety rails as always: it only touches the host you type, it's rate limited, and it won't run until you confirm you're authorized. Every finding still comes with step-by-step reproduction.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
