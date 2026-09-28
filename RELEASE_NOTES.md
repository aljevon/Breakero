## Breakero v1.10.0

### Native on Apple Silicon — no more Rosetta

The macOS download is now a universal binary. One file, but it contains both
Apple Silicon (arm64) and Intel (x86_64) code, so it runs **natively** on an
M1/M2/M3 Mac. No Rosetta, nothing extra to install, and none of the storage
Rosetta takes up. Intel Macs still run it natively too.

Nothing changes about how you use it: download `breakero-darwin-universal`,
make it runnable, and open it. The release still ships just three files.

Everything from 1.9.x is included: built-in role/IDOR dictionaries and in-app
sliders (IDOR and privilege coverage from a pasted URL, no config), the
enterprise HTML and PDF report, and the upload test-image generator.

### Downloads

Three files, one per system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-universal` for macOS (universal: Apple Silicon and Intel, native)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
