## Breakero v1.6.0

### A report that looks like a real deliverable

The HTML report has been rebuilt from the ground up to read like a professional
security-assessment document, the kind you would hand to a client or an asset
owner:

- A cover page with the target, scope, assessment date and an overall risk
  rating.
- An executive summary that states the risk posture in plain language and shows
  the count of findings at each severity.
- A risk overview with a severity breakdown, and a findings index table you can
  click straight into.
- Detailed findings, each with a clean metadata grid (endpoint, module,
  confidence, severity), evidence, business impact, recommended remediation and
  a copy-ready reproduction block.
- Methodology and scope, a verification note, and references.

### Never scroll a long report again

A fixed "Contents" dropdown sits at the top of the report. It lists every
section and every finding by its id and title, so no matter how many findings a
scan produced, any part is one click away. Every detailed finding also has a
"back to top" link.

### The mini-game got a voice

The flappy-shield game now has sound: small, playful blips for flapping,
scoring and game over, built with the Web Audio API so there are no extra files
and it works offline. A ♪ on/off toggle in the game's title bar turns it off
whenever you like.

### Easier to notice

The "play a game while you wait" button is now a filled accent button with a
gentle wiggle, so it stands out during a long scan.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
