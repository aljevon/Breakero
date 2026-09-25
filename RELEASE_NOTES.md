## Breakero v1.9.1

A small follow-up to 1.9.0.

### Fixed

- The scan progress line now settles cleanly on "100% · done" the moment a scan
  finishes, instead of briefly reading "99% · ~1s left".

### Docs

- The README and every screenshot have been refreshed to match the current app:
  the live progress and process panel, the roles & IDOR sliders that make IDOR
  and privilege testing work with no config file, the upload test-image
  generator, and the enterprise-style HTML and PDF report.

Everything from 1.9.0 is included: the built-in role/IDOR dictionaries and the
in-app sliders, so you get IDOR and privilege coverage from a pasted URL with
nothing to edit.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
