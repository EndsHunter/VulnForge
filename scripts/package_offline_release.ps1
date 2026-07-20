# Build an offline developer handoff ZIP:
#   VulnForge + Ghidra distro + ghidra-mcp (source + prebuilt jar) + docs
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\package_offline_release.ps1
#   powershell -File scripts\package_offline_release.ps1 -IncludeWheelhouse
#   powershell -File scripts\package_offline_release.ps1 -SkipGhidra
#
# Output:
#   dist\VulnForge-offline-<version>-<date>.zip

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$OutDir = "dist",
    [string]$Version = "",
    [switch]$IncludeWheelhouse,
    [switch]$SkipGhidra,
    [switch]$SkipGhidraMcp,
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

if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Copy-TreeFiltered {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Dest,
        [string[]]$ExcludeDirNames = @(),
        [string[]]$ExcludeFileGlobs = @()
    )
    if (-not (Test-Path $Source)) {
        throw "Missing source: $Source"
    }
    $src = (Resolve-Path $Source).Path
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null

    $xd = @()
    foreach ($d in $ExcludeDirNames) { $xd += @("/XD", $d) }
    $xf = @()
    foreach ($g in $ExcludeFileGlobs) { $xf += @("/XF", $g) }

    $rcArgs = @(
        $src, $Dest, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np",
        "/R:1", "/W:1"
    ) + $xd + $xf

    & robocopy @rcArgs | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) {
        throw "robocopy failed ($code) $src -> $Dest"
    }
}

# --- Core VulnForge tree ---------------------------------------------------
$vfExcludeDirs = @(
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".pytest_tmp",
    "runs", "models", "temp", "dist", "ghidra", "ghidra-mcp",
    "node_modules", ".eggs", ".mypy_cache", ".ruff_cache",
    "ghidra-mcp._local"
)
$vfExcludeFiles = @(
    "*.pyc", "*.pyo", "*.db", "*.sqlite", ".DS_Store",
    "config\ui_settings.json", "config\notepad_binary_re.yaml"
)

Write-Host "Copying VulnForge package..."
Copy-TreeFiltered -Source $RepoRoot -Dest $stage `
    -ExcludeDirNames $vfExcludeDirs `
    -ExcludeFileGlobs $vfExcludeFiles

# --- ghidra-mcp --------------------------------------------------------------
if (-not $SkipGhidraMcp) {
    $mcpSrc = Join-Path $RepoRoot "ghidra-mcp"
    if (-not (Test-Path $mcpSrc)) {
        Write-Warning "ghidra-mcp missing - binary_re offline needs it. Skipping."
    } else {
        Write-Host "Copying ghidra-mcp..."
        $mcpDest = Join-Path $stage "ghidra-mcp"
        Copy-TreeFiltered -Source $mcpSrc -Dest $mcpDest `
            -ExcludeDirNames @(".git", ".venv", "venv", ".gradle", "build", "logs", "__pycache__", ".pytest_cache") `
            -ExcludeFileGlobs @("*.pyc", ".DS_Store")

        $jar = Get-ChildItem (Join-Path $mcpSrc "build\libs\GhidraMCP*.jar") -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($jar) {
            $libs = Join-Path $mcpDest "build\libs"
            New-Item -ItemType Directory -Force -Path $libs | Out-Null
            Copy-Item $jar.FullName (Join-Path $libs $jar.Name) -Force
            $kb = [math]::Round($jar.Length / 1KB)
            Write-Host ('  included jar: ' + $jar.Name + ' (' + $kb + ' KB)')
        } else {
            Write-Warning "No GhidraMCP jar under ghidra-mcp\build\libs - offline user must build."
        }
    }
}

# --- Ghidra ------------------------------------------------------------------
if (-not $SkipGhidra) {
    $ghidraSrc = Join-Path $RepoRoot "ghidra"
    if (-not (Test-Path $ghidraSrc)) {
        Write-Warning "ghidra missing - binary_re will not run until supplied."
    } else {
        Write-Host "Copying ghidra (large - may take several minutes)..."
        $ghidraDest = Join-Path $stage "ghidra"
        Copy-TreeFiltered -Source $ghidraSrc -Dest $ghidraDest `
            -ExcludeDirNames @(".git", "__pycache__") `
            -ExcludeFileGlobs @("*.log", ".DS_Store")
    }
}

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
$offlineDoc = Join-Path $RepoRoot "docs\OFFLINE_README.md"
if (Test-Path $offlineDoc) {
    Copy-Item $offlineDoc (Join-Path $stage "OFFLINE_README.md") -Force
} else {
    "See AGENTS.md binary_re section." | Set-Content (Join-Path $stage "OFFLINE_README.md")
}

$jarName = $null
$j = Get-ChildItem (Join-Path $stage "ghidra-mcp\build\libs\GhidraMCP*.jar") -ErrorAction SilentlyContinue | Select-Object -First 1
if ($j) { $jarName = $j.Name }

$manifest = @{
    name       = $bundleName
    version    = $Version
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    includes   = @{
        vulnforge  = $true
        ghidra     = [bool](Test-Path (Join-Path $stage "ghidra"))
        ghidra_mcp = [bool](Test-Path (Join-Path $stage "ghidra-mcp"))
        wheelhouse = [bool](Test-Path (Join-Path $stage "wheelhouse"))
    }
    ghidra_mcp_jar = $jarName
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $stage "OFFLINE_MANIFEST.json") -Encoding UTF8

if ($DryRun) {
    Write-Host "DryRun: staged at $stage (no zip)"
    Get-ChildItem $stage -Name
    exit 0
}

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Write-Host "Compressing (this can take several minutes for Ghidra)..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $stageRoot,
    $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)

Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue

$zi = Get-Item $zipPath
Write-Host ""
Write-Host ("DONE: " + $zi.FullName)
Write-Host ("Size: " + [math]::Round($zi.Length / 1MB, 1) + " MB")
Write-Host ""
Write-Host "Hand this zip to an offline developer. They should read OFFLINE_README.md inside."
