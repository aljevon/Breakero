## Breakero v1.5.0

### See the scan happen

A scan used to be a spinner and a wait. Now there is a live progress line under
the checks: how far along it is as a percent, a rough estimate of the time left,
and how long it has been running.

Below that sits a process panel that reads like a terminal. It prints each check
as it starts and finishes, findings as they come in, and the calibration step at
the top. It is faint and monospace on purpose, so it looks like a log you can
glance at rather than something you have to read.

### A game while you wait

Long scans get boring. There is now a small "flappy shield" mini-game you can
open from the "play a game while you wait" button. It slides in below the
progress line, you click or press space to flap the shield through the gaps, and
it keeps your best score. Close it any time with the × in its corner. It is
entirely optional and does not touch the scan.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
