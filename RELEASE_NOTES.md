## Breakero v1.9.0

### IDOR and role testing now work with no config file

Testing for IDOR and privilege problems used to need a hand-written
`configs/example.json` describing which role holds which login and which objects
belong to whom. Now the app carries that knowledge built in, so a beginner can
paste a URL, press Scan, and get real coverage.

- A large built-in dictionary of role and permission values (admin, manager,
  editor, staff, moderator, superadmin and dozens more) is tried on blocked
  pages, the classic "role controlled by a request value" bug.
- A new automatic IDOR probe walks a dictionary of common object-id parameters
  and REST id paths (`/api/users/{id}`, `/account?id=`, and so on), reading a
  short run of sequential ids to spot guessable, unprotected object references.

### Two elegant sliders, no file to edit

The app's Advanced panel now has a "roles & idor" section:

- **role guesses** — how many role/permission values to try on each blocked page,
  from light to thorough.
- **id enumeration depth** — how many neighbouring ids the automatic IDOR probe
  reads, from shallow to deep.
- **auto-probe idor on common api paths** — on by default.

The defaults are tuned so you get IDOR and role coverage straight away without
touching anything. A config file is still there for the deeper case, where you
want to test as specific logged-in accounts and compare them.

### Tested on all three builds

Windows, Linux and macOS builds are produced from the same engine and the same
in-app interface; only the way the window opens differs. The full feature set —
scanning, the new IDOR and role coverage, and the HTML, PDF and JSON reports plus
the upload test-image generator — was exercised end to end against the shipped
binary and works the same on each.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
