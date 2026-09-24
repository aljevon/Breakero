## Breakero v1.4.1

### Report download fixed for good

Saving a report kept failing ("could not save the report" / "network issue") because the browser was being asked to download a file from the local server, and some browsers refuse http downloads. Now the report is built inside the app from the results already on screen and saved straight to a file, with no request to the server at all. Nothing to fail.

### Verify-before-you-trust note and references

The bottom of the app (and the HTML report) now spells out that these results are automated leads, not conclusions: any finding can be a false positive, a clean scan is not proof of security, and you should confirm each one by hand and dig deeper before reporting. Alongside it is a set of references to read up on the attacks:

- OWASP Top 10 2025 A01, PortSwigger access control and IDOR, OWASP Web Security Testing Guide, CWE-284, CWE-639.

### Small touch

A faint github.com/aljevon line sits at the top of the app window.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
