#!/usr/bin/env bash
# Breakero — cross-compile helper for Linux and macOS users.
# Produces static, dependency-free binaries in ./dist for every platform,
# including the Windows .exe. Requires Go 1.24+ (https://go.dev/dl/).
set -euo pipefail

BINARY="breakero"
PKG="./cmd/breakero"
DIST="dist"
BUILDFLAGS=(-trimpath -ldflags "-s -w")

command -v go >/dev/null 2>&1 || { echo "Go is not installed. Get it at https://go.dev/dl/"; exit 1; }

echo "Breakero build — Go $(go version | awk '{print $3}')"
rm -rf "$DIST"
mkdir -p "$DIST"

build() {
  local goos="$1" goarch="$2" out="$3"
  echo "  -> $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build "${BUILDFLAGS[@]}" -o "$DIST/$out" "$PKG"
}

build windows amd64 "${BINARY}-windows-amd64.exe"
build windows arm64 "${BINARY}-windows-arm64.exe"
build linux   amd64 "${BINARY}-linux-amd64"
build linux   arm64 "${BINARY}-linux-arm64"
build darwin  amd64 "${BINARY}-darwin-amd64"
build darwin  arm64 "${BINARY}-darwin-arm64"

echo
echo "Done. Binaries in ./$DIST:"
ls -lh "$DIST"
