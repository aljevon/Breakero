## Breakero v1.8.0

### Save the report as PDF

There is now a "pdf" button next to the html and json downloads. It opens the
report in the print dialog, where you pick "Save as PDF" (or "Microsoft Print to
PDF" on Windows). The report carries a dedicated print stylesheet, so the PDF
comes out as a clean, legible light-on-white document instead of the dark
on-screen theme. For accurate totals, save it after the scan finishes.

### Upload test image generator

A new "upload test image" panel builds a real, valid image you can use to probe
Broken Access Control on image-upload features (upload forms, avatars, document
fields, anything that accepts a picture).

- Choose PNG or JPG and a target size: about 200 KB, 500 KB, 1 MB, or under 2 MB.
- The generated image is a genuine, viewable file with a unique "canary" token
  and benign access-control probe notes embedded in its metadata.
- Upload it through the target's own image field, then check whether the stored
  file is reachable without a session, guessable by id (IDOR), served with its
  metadata intact, or returned to another user. The canary makes your file easy
  to locate in responses and URLs.

Nothing is uploaded for you: the tool only writes a local file, so you stay in
control of the actual request, the same way Breakero's findings hand you the
exact steps to confirm by hand. Only test uploads you are authorized to test.

### Downloads

Three files, one for each system:

- `breakero-windows-amd64.exe` for Windows (64-bit)
- `breakero-linux-amd64` for Linux (64-bit)
- `breakero-darwin-amd64` for macOS (64-bit; runs on Apple Silicon through Rosetta)

Please only use it on things you're allowed to test. See AUTHORIZATION.md.
