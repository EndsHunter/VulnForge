# Build an offline developer handoff ZIP of VulnForge (source analysis only).
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\package_offline_release.ps1
#   powershell -File scripts\package_offline_release.ps1 -IncludeWheelhouse
#
# Output:
#   dist\VulnForge-offline-<version>-<date>.zip

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$OutDir = "dist",
    [string]$Version = "",
    [switch]$IncludeWheelhouse,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
$RepoRoot = (Resolve-Path $RepoRoot).Path
Set-Location $RepoRoot

if (-not $Version) {
    $pyproject = Join-Path $RepoRoot "pyproject.toml"
    if (Test-Path $pyproject) {
        $m = Select-String -Path $pyproject -Pattern 'version\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { $Version = $m.Matches.Groups[1].Value }
    }
    if (-not $Version) { $Version = "0.1.0" }
}

$stamp = Get-Date -Format "yyyyMMdd"
$bundleName = "VulnForge-offline-$Version-$stamp"
$stageRoot = Join-Path $env:TEMP "vf-offline-$stamp-$PID"
$stage = Join-Path $stageRoot $bundleName
$outAbs = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $outAbs | Out-Null
$zipPath = Join-Path $outAbs "$bundleName.zip"

Write-Host "Repo:   $RepoRoot"
Write-Host "Stage:  $stage"
Write-Host "Zip:    $zipPath"

if (Test-Path $stageRoot) { Remove-Item -Recurse -Force $stageRoot }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Copy-TreeFiltered {
    param(
        [string]$Source,
        [string]$Dest,
        [string[]]$ExcludeDirNames = @(),
        [string[]]$ExcludeFileGlobs = @()
    )
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    $xd = @()
    foreach ($d in $ExcludeDirNames) { $xd += @("/XD", $d) }
    $xf = @()
    foreach ($g in $ExcludeFileGlobs) { $xf += @("/XF", $g) }
    $src = (Resolve-Path $Source).Path
    # robocopy: 0-7 success
    & robocopy $src $Dest /E /NFL /NDL /NJH /NJS /nc /ns /np @xd @xf | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) {
        throw "robocopy failed ($code) $src -> $Dest"
    }
}

# --- Core VulnForge tree ---------------------------------------------------
$vfExcludeDirs = @(
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".pytest_tmp",
    "runs", "models", "temp", "dist",
    "node_modules", ".eggs", ".mypy_cache", ".ruff_cache"
)
$vfExcludeFiles = @(
    "*.pyc", "*.pyo", "*.db", "*.sqlite", ".DS_Store",
    "config\ui_settings.json"
)

Write-Host "Copying VulnForge package..."
Copy-TreeFiltered -Source $RepoRoot -Dest $stage `
    -ExcludeDirNames $vfExcludeDirs `
    -ExcludeFileGlobs $vfExcludeFiles

# --- Optional pip wheelhouse -------------------------------------------------
if ($IncludeWheelhouse) {
    Write-Host "Downloading Python wheels into wheelhouse (requires network once)..."
    $wh = Join-Path $stage "wheelhouse"
    New-Item -ItemType Directory -Force -Path $wh | Out-Null
    $req = Join-Path $stage "requirements-offline.txt"
    @(
        "httpx>=0.27",
        "pyyaml>=6.0",
        "fastapi>=0.115",
        "uvicorn[standard]>=0.30",
        "jinja2>=3.1",
        "openpyxl>=3.1",
        "python-docx>=1.1",
        "pypdf>=4.0",
        "pytest>=8.0"
    ) | Set-Content -Path $req -Encoding UTF8
    py -3 -m pip download -r $req -d $wh
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "pip download failed - wheelhouse incomplete"
    } else {
        Write-Host "  wheelhouse ready"
    }
}

# --- Offline docs ------------------------------------------------------------
@"
# VulnForge offline package

Source-code analysis harness (code_static only).

## Setup

``````powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
# if wheelhouse present:
pip install --no-index --find-links=wheelhouse -e ".[dev]"
# otherwise (network):
pip install -e ".[dev]"
vf dashboard
``````

See AGENTS.md and README.md for operator docs.
"@ | Set-Content (Join-Path $stage "OFFLINE_README.md") -Encoding UTF8

$manifest = @{
    name       = $bundleName
    version    = $Version
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    includes   = @{
        vulnforge  = $true
        wheelhouse = [bool](Test-Path (Join-Path $stage "wheelhouse"))
    }
    scope      = "source_code_analysis"
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $stage "OFFLINE_MANIFEST.json") -Encoding UTF8

if ($DryRun) {
    Write-Host "DryRun: staged at $stage (no zip)"
    Get-ChildItem $stage -Name
    exit 0
}

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Write-Host "Compressing..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath)
Remove-Item -Recurse -Force $stageRoot
Write-Host "Wrote $zipPath"
