<#
.SYNOPSIS
  Start the VulnForge dashboard (Windows). Linux / macOS: use ./start.sh.

.DESCRIPTION
  Installs first if needed. Extra arguments go to `vf dashboard`.

  Easiest: double-click start.cmd, or run it from a terminal:

    start.cmd                  -> http://127.0.0.1:8787
    start.cmd --port 8788
#>
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if ($env:OS -eq 'Windows_NT') {
    $VenvVf = Join-Path '.venv' (Join-Path 'Scripts' 'vf.exe')
} else {
    $VenvVf = Join-Path '.venv' (Join-Path 'bin' 'vf')
}

if (-not (Test-Path -LiteralPath $VenvVf)) {
    Write-Host 'VulnForge is not installed yet; running the installer first.'
    & (Join-Path $PSScriptRoot 'install.ps1')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host ''
}

& $VenvVf dashboard @args
exit $LASTEXITCODE
