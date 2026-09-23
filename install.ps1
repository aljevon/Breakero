# Breakero - all-in-one installer for Windows (PowerShell).
#
# Detects your CPU, downloads the matching .exe from the latest GitHub release,
# installs it under %LOCALAPPDATA%\Breakero, and adds that folder to your user
# PATH. Re-run any time to upgrade.
#
#   irm https://raw.githubusercontent.com/aljevon/Breakero/breakero/install.ps1 | iex
#
# Optional: set $env:BREAKERO_VERSION to install a specific release tag.

$ErrorActionPreference = "Stop"
$Repo = "aljevon/Breakero"

function Info($m) { Write-Host "  * $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Breakero installer - Broken Access Control Scanner" -ForegroundColor White
Write-Host ""

# Detect architecture.
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$asset = "breakero-windows-$arch.exe"
Info "Detected: windows/$arch  ->  $asset"

# Resolve the download URL.
if ($env:BREAKERO_VERSION) {
    $url = "https://github.com/$Repo/releases/download/$($env:BREAKERO_VERSION)/$asset"
    Info "Version: $($env:BREAKERO_VERSION)"
} else {
    $url = "https://github.com/$Repo/releases/latest/download/$asset"
    Info "Version: latest"
}

# Install location.
$dir = Join-Path $env:LOCALAPPDATA "Breakero"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dest = Join-Path $dir "breakero.exe"

Info "Downloading $asset..."
try {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
} catch {
    throw "Download failed. Check that a release exists at https://github.com/$Repo/releases"
}
Ok "Installed to $dest"

# Add to user PATH if missing.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    $env:Path = "$env:Path;$dir"
    Ok "Added $dir to your user PATH (restart your terminal to pick it up everywhere)."
} else {
    Info "$dir is already on your PATH."
}

Write-Host ""
Ok "Done. Try it out:"
Write-Host "        breakero -explain"
Write-Host ""
Warn "Reminder: only test systems you are authorized to test. See AUTHORIZATION.md"
Write-Host ""
