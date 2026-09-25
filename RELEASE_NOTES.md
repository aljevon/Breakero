## Breakero v1.7.0

### The in-app report is now the premium one

The report you download from inside the app used to have a much plainer layout
than the one the command line produced. Now they are the same premium
security-assessment document, the kind you would hand to a client or an asset
owner:

- A cover page with the target, scope, assessment date, a report reference and
  an overall risk rating.
- An executive summary that states the risk posture in plain language, with a
  count of findings at each severity.
- A risk overview with a severity breakdown, and a findings index you can click
  straight into.
- Detailed findings, each with a clean metadata grid (endpoint, module,
  confidence, severity), evidence, business impact, recommended remediation and
  a copy-ready reproduction block.
- Methodology and scope, a verification note, and references.
- The fixed "Contents" dropdown at the top, so a long report with many findings
  is one click from any section instead of a scroll.

### More accurate

- The severity counts and the overall risk rating are now taken from the
  findings themselves, so the summary always matches the detailed list.
- A report saved in the middle of a scan no longer shows a misleading "0.0s"
  duration; it shows the live elapsed time until the final total is ready. For
  the complete picture, download after the scan finishes.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
