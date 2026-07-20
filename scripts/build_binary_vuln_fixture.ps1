# Build fixtures/binary_vuln/vuln_copy.exe — intentional strcpy research fixture.
# Prefers MSVC (cl) x64, then gcc / x86_64-w64-mingw32-gcc.
# Does not execute the resulting binary.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $RepoRoot "fixtures\binary_vuln\src\vuln_copy.c"))) {
    # Allow running when script lives next to fixtures (flat layout)
    $RepoRoot = $PSScriptRoot
    if (-not (Test-Path (Join-Path $RepoRoot "fixtures\binary_vuln\src\vuln_copy.c"))) {
        $RepoRoot = Get-Location
    }
}

$Src = Join-Path $RepoRoot "fixtures\binary_vuln\src\vuln_copy.c"
$OutDir = Join-Path $RepoRoot "fixtures\binary_vuln"
$OutExe = Join-Path $OutDir "vuln_copy.exe"

if (-not (Test-Path $Src)) {
    Write-Error "Source not found: $Src"
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Find-Cl {
    $onPath = Get-Command cl -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    $vcvarsCandidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )
    foreach ($bat in $vcvarsCandidates) {
        if (Test-Path $bat) {
            return @{ Vcvars = $bat }
        }
    }
    return $null
}

function Find-Gcc {
    foreach ($name in @("gcc", "x86_64-w64-mingw32-gcc")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    $hints = @(
        "C:\msys64\mingw64\bin\gcc.exe",
        "C:\mingw64\bin\gcc.exe",
        "C:\TDM-GCC-64\bin\gcc.exe"
    )
    foreach ($h in $hints) {
        if (Test-Path $h) { return $h }
    }
    return $null
}

# Flags keep the intentional sink visible to static RE:
#   /MD          — dynamic UCRT so strcpy is an IAT import (api-ms-win-crt-string-*)
#   /Od /Oi- /Ob0 — no opt / no strcpy intrinsic / no inline
#   /EXPORT:vulnerable_copy — PE export name for ground-truth symbol recovery
# Does not execute the binary.

function Invoke-MsvcBuild {
    param([string]$ClExe = "cl")
    $obj = Join-Path $OutDir "vuln_copy.obj"
    # Discard compiler stdout so it is not captured as the function return value.
    $null = & $ClExe /nologo /MD /Od /Oi- /Ob0 /W3 /D_CRT_SECURE_NO_WARNINGS /TC $Src `
        /Fe:$OutExe /Fo:$obj /link /DEBUG:NONE /EXPORT:vulnerable_copy 2>&1
    $ec = $LASTEXITCODE
    foreach ($extra in @($obj, (Join-Path $OutDir "vuln_copy.exp"), (Join-Path $OutDir "vuln_copy.lib"), (Join-Path $OutDir "vuln_copy.ilk"))) {
        if (Test-Path $extra) { Remove-Item $extra -Force -ErrorAction SilentlyContinue }
    }
    return ,$ec
}

function Find-DirectCl {
    $roots = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise"
    )
    foreach ($root in $roots) {
        $msvcRoot = Join-Path $root "VC\Tools\MSVC"
        if (-not (Test-Path $msvcRoot)) { continue }
        $ver = Get-ChildItem $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $ver) { continue }
        $clPath = Join-Path $ver.FullName "bin\Hostx64\x64\cl.exe"
        if (-not (Test-Path $clPath)) { continue }
        $kitsInc = "C:\Program Files (x86)\Windows Kits\10\Include"
        $kitsLib = "C:\Program Files (x86)\Windows Kits\10\Lib"
        if (-not (Test-Path $kitsInc)) { continue }
        $sdkInc = Get-ChildItem $kitsInc -Directory | Sort-Object Name -Descending | Select-Object -First 1
        $sdkLib = Get-ChildItem $kitsLib -Directory | Sort-Object Name -Descending | Select-Object -First 1
        return @{
            Cl      = $clPath
            Bin     = Join-Path $ver.FullName "bin\Hostx64\x64"
            Include = @(
                (Join-Path $ver.FullName "include"),
                (Join-Path $sdkInc.FullName "ucrt"),
                (Join-Path $sdkInc.FullName "shared"),
                (Join-Path $sdkInc.FullName "um")
            ) -join ";"
            Lib     = @(
                (Join-Path $ver.FullName "lib\x64"),
                (Join-Path $sdkLib.FullName "ucrt\x64"),
                (Join-Path $sdkLib.FullName "um\x64")
            ) -join ";"
        }
    }
    return $null
}

$built = $false
$onPathCl = Get-Command cl -ErrorAction SilentlyContinue
if ($onPathCl) {
    Write-Host "Using cl on PATH: $($onPathCl.Source)"
    $ec = Invoke-MsvcBuild -ClExe "cl"
    if ($ec -ne 0) { Write-Error "MSVC build failed (exit $ec)"; exit $ec }
    $built = $true
}

if (-not $built) {
    $direct = Find-DirectCl
    if ($direct) {
        Write-Host "Using MSVC direct: $($direct.Cl)"
        $env:PATH = "$($direct.Bin);$env:PATH"
        $env:INCLUDE = $direct.Include
        $env:LIB = $direct.Lib
        $ec = Invoke-MsvcBuild -ClExe $direct.Cl
        if ($ec -ne 0) { Write-Error "MSVC build failed (exit $ec)"; exit $ec }
        $built = $true
    }
}

if (-not $built) {
    $clInfo = Find-Cl
    if ($clInfo -is [hashtable] -and $clInfo.Vcvars) {
        Write-Host "Using MSVC via $($clInfo.Vcvars)"
        $obj = Join-Path $OutDir "vuln_copy.obj"
        $bat = @"
@echo off
call "$($clInfo.Vcvars)" >nul
if errorlevel 1 exit /b 1
cl /nologo /MD /Od /Oi- /Ob0 /W3 /D_CRT_SECURE_NO_WARNINGS /TC "$Src" /Fe:"$OutExe" /Fo:"$obj" /link /DEBUG:NONE /EXPORT:vulnerable_copy
set EC=%ERRORLEVEL%
if exist "$obj" del /q "$obj"
if exist "$(Join-Path $OutDir 'vuln_copy.exp')" del /q "$(Join-Path $OutDir 'vuln_copy.exp')"
if exist "$(Join-Path $OutDir 'vuln_copy.lib')" del /q "$(Join-Path $OutDir 'vuln_copy.lib')"
exit /b %EC%
"@
        $tmpBat = Join-Path $env:TEMP "vf_build_binary_vuln_$PID.bat"
        Set-Content -Path $tmpBat -Value $bat -Encoding ASCII
        try {
            $p = Start-Process -FilePath $tmpBat -Wait -PassThru -NoNewWindow
            if ($p.ExitCode -ne 0) {
                Write-Error "MSVC build failed (exit $($p.ExitCode))"
                exit $p.ExitCode
            }
            $built = $true
        } finally {
            Remove-Item $tmpBat -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not $built) {
    $gcc = Find-Gcc
    if (-not $gcc) {
        Write-Error @"
No C compiler found (cl / gcc / x86_64-w64-mingw32-gcc).
Install MSVC Build Tools or MinGW, or compile manually — see fixtures/binary_vuln/README.md.
Source remains at: $Src
"@
        exit 2
    }
    Write-Host "Using gcc: $gcc"
    # -fno-builtin-strcpy keeps an external strcpy reference; -O0 preserves the sink.
    & $gcc -O0 -fno-builtin-strcpy -o $OutExe $Src
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $built = $true
}

if (-not (Test-Path $OutExe)) {
    Write-Error "Build reported success but $OutExe is missing"
    exit 1
}

$bytes = (Get-Item $OutExe).Length
# MZ header check only — do not run the binary
$fs = [System.IO.File]::OpenRead($OutExe)
try {
    $mz = New-Object byte[] 2
    [void]$fs.Read($mz, 0, 2)
} finally {
    $fs.Close()
}
if ($mz[0] -ne 0x4D -or $mz[1] -ne 0x5A) {
    Write-Error "Output is not a PE (missing MZ): $OutExe"
    exit 1
}

Write-Host "OK: $OutExe ($bytes bytes, MZ PE)"
exit 0
