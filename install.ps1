<#
.SYNOPSIS
  VulnForge installer (Windows). Linux / macOS: use ./install.sh.

.DESCRIPTION
  Creates .\.venv and installs the `vf` command into it. Nothing outside this
  folder is touched. Safe to re-run: after `git pull`, or to repair a broken
  environment.

  Easiest: double-click install.cmd, or run it from a terminal. To call this
  script directly:

    powershell -ExecutionPolicy Bypass -File install.ps1
    powershell -ExecutionPolicy Bypass -File install.ps1 -Recreate   # delete .venv, start over
    powershell -ExecutionPolicy Bypass -File install.ps1 -NoDev      # skip the test tools (pytest)

  Set the PYTHON environment variable to use a specific python.exe.
#>
param(
    [switch]$Recreate,
    [switch]$NoDev
)

$ErrorActionPreference = 'Stop'
$MinMinor = 11        # Python 3.11+. Keep in sync with requires-python in pyproject.toml.
$UvFallback = '3.12'  # what uv fetches when no installed Python is new enough (the CI version)

Set-Location -LiteralPath $PSScriptRoot

# Windows venvs use Scripts\ and .exe; the other branch keeps this testable under pwsh on Linux.
$OnWindows = ($env:OS -eq 'Windows_NT')
if ($OnWindows) {
    $VenvPy = Join-Path '.venv' (Join-Path 'Scripts' 'python.exe')
    $VenvVf = Join-Path '.venv' (Join-Path 'Scripts' 'vf.exe')
} else {
    $VenvPy = Join-Path '.venv' (Join-Path 'bin' 'python')
    $VenvVf = Join-Path '.venv' (Join-Path 'bin' 'vf')
}

function Fail([string]$Message) {
    Write-Host ''
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

# Runs `<command> -c <code>` and returns its one line of output, or $null.
# Never throws: the Microsoft Store "python" stub and a missing `py -3.x` both land here.
function Invoke-Py([string[]]$Command, [string]$Code) {
    try {
        $exe = $Command[0]
        $rest = @($Command | Select-Object -Skip 1)
        $out = & $exe @rest -c $Code 2>$null
        if ($LASTEXITCODE -eq 0 -and $null -ne $out) {
            return ([string]($out | Select-Object -First 1)).Trim()
        }
    } catch {
    }
    return $null
}

function Test-PyOk([string[]]$Command) {
    $ok = Invoke-Py $Command "import sys; print('ok' if sys.version_info >= (3, $MinMinor) else 'old')"
    return ($ok -eq 'ok')
}

function Get-PyVersion([string[]]$Command) {
    return Invoke-Py $Command "import sys; print('%d.%d' % sys.version_info[:2])"
}

# Full path of an installed interpreter that is new enough, or $null.
function Find-Python {
    if ($env:PYTHON) {
        return $env:PYTHON
    }
    $candidates = @('python', 'py -3', 'py -3.13', 'py -3.12', 'py -3.11', 'py -3.14', 'py -3.15', 'python3')
    foreach ($candidate in $candidates) {
        $parts = $candidate -split ' '
        if (-not (Get-Command $parts[0] -ErrorAction SilentlyContinue)) { continue }
        if (Test-PyOk $parts) {
            return Invoke-Py $parts 'import sys; print(sys.executable)'
        }
    }
    return $null
}

function Test-VenvUsable {
    if (-not (Test-Path -LiteralPath $VenvPy)) { return $false }
    if (-not (Test-PyOk @($VenvPy))) { return $false }
    return ($null -ne (Invoke-Py @($VenvPy) 'import pip; print(pip.__version__)'))
}

if (-not ((Test-Path -LiteralPath 'pyproject.toml') -and (Test-Path -LiteralPath 'vulnforge'))) {
    Fail 'run this from a full VulnForge checkout (pyproject.toml and vulnforge\ must sit next to install.ps1).'
}
if ($env:PYTHON -and -not (Test-PyOk @($env:PYTHON))) {
    Fail "PYTHON=$($env:PYTHON) is not a working Python 3.$MinMinor or newer."
}

$uvCommand = Get-Command uv -ErrorAction SilentlyContinue
$uv = $null
if ($uvCommand) { $uv = $uvCommand.Source }

# --- 1. virtual environment -------------------------------------------------
if (Test-Path -LiteralPath '.venv') {
    if ($Recreate -or -not (Test-VenvUsable)) {
        $isVenv = Test-Path -LiteralPath (Join-Path '.venv' 'pyvenv.cfg')
        $isEmpty = -not (Get-ChildItem -LiteralPath '.venv' -Force | Select-Object -First 1)
        if (-not ($isVenv -or $isEmpty)) {
            Fail '.venv exists but is not a Python virtual environment. Move it aside and re-run.'
        }
        if ($Recreate) {
            Write-Host 'Removing .venv (-Recreate) ...'
        } else {
            Write-Host 'Existing .venv is broken or too old; rebuilding it ...'
        }
        Remove-Item -LiteralPath '.venv' -Recurse -Force
    } else {
        Write-Host "Using existing .venv (Python $(Get-PyVersion @($VenvPy)))."
    }
}

if (-not (Test-Path -LiteralPath '.venv')) {
    $python = Find-Python
    if ($uv) {
        if ($python) {
            Write-Host "Creating .venv with uv (Python $(Get-PyVersion @($python))) ..."
            & $uv venv --quiet --seed --python $python .venv
        } else {
            Write-Host "Creating .venv with uv (downloading Python $UvFallback; no installed Python 3.$MinMinor+ found) ..."
            & $uv venv --quiet --seed --python $UvFallback .venv
        }
        if ($LASTEXITCODE -ne 0) { Fail 'uv could not create .venv.' }
    } elseif ($python) {
        Write-Host "Creating .venv with $python (Python $(Get-PyVersion @($python))) ..."
        & $python -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            if (Test-Path -LiteralPath '.venv') { Remove-Item -LiteralPath '.venv' -Recurse -Force }
            Fail "Python could not create a virtual environment (its venv module is missing or broken). Reinstall Python from https://www.python.org/downloads/ and run the installer again."
        }
    } else {
        Write-Host ''
        Write-Host "VulnForge needs Python 3.$MinMinor or newer, and none was found on this machine."
        Write-Host ''
        Write-Host 'Install it one of these ways, open a NEW terminal, then run the installer again:'
        Write-Host '  winget install Python.Python.3.13'
        Write-Host '  https://www.python.org/downloads/      (tick "Add python.exe to PATH")'
        Write-Host '  winget install astral-sh.uv            (uv downloads Python for you)'
        exit 1
    }
}
if (-not (Test-VenvUsable)) {
    Fail '.venv was created but is not usable. Run the installer again with -Recreate.'
}

# --- 2. package + dependencies ----------------------------------------------
Write-Host 'Installing VulnForge and its dependencies (a minute or so the first time) ...'
$spec = '.[dev]'
if ($NoDev) { $spec = '.' }
if ($uv) {
    & $uv pip install --quiet --python $VenvPy -e $spec
} else {
    $env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
    & $VenvPy -m pip install -qq -e $spec
}
if ($LASTEXITCODE -ne 0) {
    Fail 'dependency install failed (see above). Check your network / proxy, then run the installer again.'
}

# --- 3. verify ---------------------------------------------------------------
& $VenvVf --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "installed, but 'vf --help' does not run. Run the installer again with -Recreate."
}

Write-Host ''
Write-Host "VulnForge is installed (Python $(Get-PyVersion @($VenvPy)), in .venv)."
Write-Host ''
if ($OnWindows) {
    Write-Host '  Start the dashboard    start.cmd                          -> http://127.0.0.1:8787'
    Write-Host '  Use the CLI            .venv\Scripts\vf.exe --help'
    Write-Host '                         (or activate once: .venv\Scripts\Activate.ps1, then: vf --help)'
    Write-Host '  Try the toy target     .venv\Scripts\vf.exe init --target fixtures\toy_sqli'
    Write-Host ''
    Write-Host "Re-run install.cmd after 'git pull' to pick up new dependencies."
} else {
    Write-Host '  Start the dashboard    ./start.sh                  -> http://127.0.0.1:8787'
    Write-Host '  Use the CLI            source .venv/bin/activate   then: vf --help'
}
exit 0
