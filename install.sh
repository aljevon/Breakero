#!/usr/bin/env sh
# Breakero — all-in-one installer for macOS and Linux.
#
# It detects your OS and CPU, downloads the matching binary from the latest
# GitHub release, and installs it onto your PATH. No dependencies beyond curl
# (or wget). Re-run it any time to upgrade to the newest release.
#
#   curl -fsSL https://raw.githubusercontent.com/aljevon/Breakero/breakero/install.sh | sh
#
# Environment overrides:
#   BREAKERO_VERSION=v1.2.3   install a specific release instead of the latest
#   BREAKERO_INSTALL_DIR=...   install to a specific directory
set -eu

REPO="aljevon/Breakero"
BIN="breakero"

info()  { printf '  \033[1;36m%s\033[0m %s\n' "•" "$*"; }
ok()    { printf '  \033[1;32m%s\033[0m %s\n' "✓" "$*"; }
warn()  { printf '  \033[1;33m%s\033[0m %s\n' "!" "$*"; }
die()   { printf '  \033[1;31m%s\033[0m %s\n' "✗" "$*" >&2; exit 1; }

printf '\n  \033[1mBreakero installer\033[0m — Broken Access Control Scanner\n\n'

# --- Detect OS ---
os="$(uname -s)"
case "$os" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  *) die "Unsupported OS: $os (this installer is for macOS and Linux; on Windows use install.ps1)" ;;
esac

# --- Detect architecture ---
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)        arch="amd64" ;;
  aarch64|arm64)       arch="arm64" ;;
  *) die "Unsupported CPU architecture: $arch" ;;
esac

asset="${BIN}-${os}-${arch}"
info "Detected: ${os}/${arch}  ->  ${asset}"

# --- Build the download URL ---
if [ "${BREAKERO_VERSION:-}" = "" ]; then
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
  info "Version: latest"
else
  url="https://github.com/${REPO}/releases/download/${BREAKERO_VERSION}/${asset}"
  info "Version: ${BREAKERO_VERSION}"
fi

# --- Pick a downloader ---
download() { # download <url> <dest>
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "Neither curl nor wget is installed."
  fi
}

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t breakero)"
trap 'rm -rf "$tmp"' EXIT
info "Downloading ${asset}..."
download "$url" "$tmp/$BIN" || die "Download failed. Check that a release exists at https://github.com/${REPO}/releases"
chmod +x "$tmp/$BIN"

# --- Choose an install directory on PATH ---
if [ -n "${BREAKERO_INSTALL_DIR:-}" ]; then
  dir="$BREAKERO_INSTALL_DIR"
elif [ -w "/usr/local/bin" ] 2>/dev/null; then
  dir="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -d "/usr/local/bin" ]; then
  dir="/usr/local/bin"
  SUDO="sudo"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" 2>/dev/null || { SUDO="sudo"; ${SUDO:-} mkdir -p "$dir"; }

# --- Install ---
if [ "${SUDO:-}" = "sudo" ]; then
  warn "Installing to $dir needs elevated permissions; you may be prompted."
  sudo mv "$tmp/$BIN" "$dir/$BIN"
else
  mv "$tmp/$BIN" "$dir/$BIN"
fi
ok "Installed to $dir/$BIN"

# --- PATH hint ---
case ":$PATH:" in
  *":$dir:"*) : ;;
  *)
    warn "$dir is not on your PATH yet. Add this line to your shell profile:"
    printf '        export PATH="%s:$PATH"\n' "$dir"
    ;;
esac

printf '\n'
ok "Done. Try it out:"
printf '        %s -explain\n\n' "$BIN"
warn "Reminder: only test systems you are authorized to test. See AUTHORIZATION.md"
printf '\n'
