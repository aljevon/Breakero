# Breakero - cross-compile helper for Windows users (PowerShell).
# Produces static, dependency-free binaries in .\dist for every platform.
# Requires Go 1.24+  (https://go.dev/dl/).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\build.ps1

$ErrorActionPreference = "Stop"

$Binary = "breakero"
$Pkg    = "./cmd/breakero"
$Dist   = "dist"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is not installed. Get it at https://go.dev/dl/"
    exit 1
}

Write-Host "Breakero build - $(go version)"
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Path $Dist | Out-Null

function Build($goos, $goarch, $out) {
    Write-Host "  -> $out"
    $env:CGO_ENABLED = "0"
    $env:GOOS   = $goos
    $env:GOARCH = $goarch
    go build -trimpath -ldflags "-s -w" -o "$Dist/$out" $Pkg
}

Build "windows" "amd64" "$Binary-windows-amd64.exe"
Build "windows" "arm64" "$Binary-windows-arm64.exe"
Build "linux"   "amd64" "$Binary-linux-amd64"
Build "linux"   "arm64" "$Binary-linux-arm64"
Build "darwin"  "amd64" "$Binary-darwin-amd64"
Build "darwin"  "arm64" "$Binary-darwin-arm64"

# Reset env vars to build for the local machine afterwards.
Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. Binaries in .\$Dist:"
Get-ChildItem $Dist | Format-Table Name, Length
