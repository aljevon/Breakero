## Breakero v1.11.0

### Test behind the login

Many access-control bugs only appear once you're signed in. The app now has a
**post-login sessions** panel: paste one or more logged-in sessions — a cookie
and/or an auth header, with a privilege level and, optionally, the object ids
each account owns — and Breakero scans *behind* the login.

With two sessions it compares them to find the two classic authenticated bugs:

- **Vertical privilege escalation** — a low-privilege session reaching a page or
  action that should need a higher role (a normal user opening `/admin`). This
  now works with no config file, against the built-in sensitive-path list.
- **Cross-account IDOR / BOLA** — one session reading another account's objects
  by id.

It stays strictly **read-only**: it only sends GET requests to see what each
session can reach, and reports it. It never changes or extracts data. Use it only
on systems you own or are authorized to test — a deliberately vulnerable lab
(OWASP Juice Shop, PortSwigger Web Security Academy, DVWA) is the place to learn.

The old single "session cookie" field moved into this panel, which now supports
several sessions and auth headers.

### Downloads

Three files, one per system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-universal` for macOS (universal: Apple Silicon and Intel, native)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
