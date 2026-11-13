#!/bin/sh
# VulnForge installer (Linux / macOS). Windows: use install.ps1.
#
# Creates ./.venv and installs the `vf` command into it. Nothing outside this
# folder is touched, unless no usable Python is found and you agree to let it
# download uv (a standalone Python manager) into ~/.local.
# Safe to re-run: after `git pull`, or to repair a broken environment.
#
#   ./install.sh               install or update
#   ./install.sh --recreate    delete .venv and start over
#   ./install.sh --yes         download uv without asking, if it is needed
#   ./install.sh --no-dev      skip the test tools (pytest)
#   PYTHON=/path/to/python3.12 ./install.sh    use a specific interpreter
set -eu

MIN_MINOR=11        # Python 3.11+. Keep in sync with requires-python in pyproject.toml.
UV_FALLBACK=3.12    # what uv fetches when no system Python is new enough (the CI version)

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

VENV_PY=.venv/bin/python
RECREATE=0
YES=0
SPEC='.[dev]'

say() { printf '%s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case $arg in
    --recreate) RECREATE=1 ;;
    --yes|-y) YES=1 ;;
    --no-dev) SPEC='.' ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $arg" ;;
  esac
done

case $(uname -s 2>/dev/null) in
  MINGW*|MSYS*|CYGWIN*)
    die "this is the Linux/macOS installer. On Windows run:  powershell -ExecutionPolicy Bypass -File install.ps1" ;;
esac

[ -f pyproject.toml ] && [ -d vulnforge ] ||
  die "run this from a full VulnForge checkout (pyproject.toml and vulnforge/ must sit next to install.sh)."

LOG=$(mktemp "${TMPDIR:-/tmp}/vf-install.XXXXXX")
trap 'rm -f "$LOG"' EXIT

py_version() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null; }
py_ok() { "$1" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_MINOR) else 1)" 2>/dev/null; }

if [ -n "${PYTHON:-}" ] && ! py_ok "$PYTHON"; then
  die "PYTHON=$PYTHON is not a working Python 3.$MIN_MINOR or newer."
fi

# A system interpreter that is new enough, or nothing.
find_python() {
  if [ -n "${PYTHON:-}" ]; then
    printf '%s\n' "$PYTHON"
    return 0
  fi
  for c in python3 python3.13 python3.12 python3.11 python3.14 python3.15 python; do
    if command -v "$c" >/dev/null 2>&1 && py_ok "$c"; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# uv on PATH, or where its installer puts it.
find_uv() {
  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi
  for c in "${XDG_BIN_HOME:-$HOME/.local/bin}/uv" "$HOME/.cargo/bin/uv"; do
    if [ -x "$c" ]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

venv_usable() {
  [ -x "$VENV_PY" ] && py_ok "$VENV_PY" && "$VENV_PY" -m pip --version >/dev/null 2>&1
}

show_log() {
  say ""
  say "---- last lines of the failing step ----"
  tail -n 30 "$LOG" >&2
  say "----------------------------------------"
}

uv_venv() {
  # Prefer a system interpreter; otherwise uv downloads its own.
  if sel=$(find_python); then
    say "Creating .venv with uv (Python $(py_version "$sel")) ..."
  else
    sel=$UV_FALLBACK
    say "Creating .venv with uv (downloading Python $sel; no system Python 3.$MIN_MINOR+ found) ..."
  fi
  if ! "$1" venv --seed --python "$sel" .venv >"$LOG" 2>&1; then
    show_log
    die "uv could not create .venv."
  fi
}

download_uv() {
  url=https://astral.sh/uv/install.sh
  script=$(mktemp "${TMPDIR:-/tmp}/vf-uv.XXXXXX")
  say "Downloading uv ..."
  if command -v curl >/dev/null 2>&1; then
    curl -LsSf "$url" -o "$script" || { rm -f "$script"; die "could not download $url (network or proxy?)."; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$script" || { rm -f "$script"; die "could not download $url (network or proxy?)."; }
  else
    rm -f "$script"
    die "curl or wget is needed to download uv. Install one, or use fix 1 above."
  fi
  # UV_NO_MODIFY_PATH: put the binary in ~/.local/bin and leave shell profiles alone.
  if ! UV_NO_MODIFY_PATH=1 sh "$script" >"$LOG" 2>&1; then
    rm -f "$script"
    show_log
    die "the uv installer failed."
  fi
  rm -f "$script"
}

# No usable interpreter: explain, then offer uv.
offer_uv() {
  say ""
  say "$1"
  say ""
  say "Two ways to fix it:"
  say "  1. $2"
  say "     then run ./install.sh again."
  say "  2. Let this script download uv (https://docs.astral.sh/uv): one binary in"
  say "     ~/.local/bin that brings its own Python (kept under ~/.local/share/uv)."
  say "     Your system Python and shell profile are left alone."
  say ""
  if [ "$YES" != 1 ]; then
    if [ -t 0 ]; then
      printf 'Download uv now? [Y/n] '
      read -r answer || answer=n
      case $answer in
        ''|y|Y|yes|Yes|YES) ;;
        *) say "Nothing installed."; exit 1 ;;
      esac
    else
      say "Not a terminal, so not asking. Re-run with --yes to take fix 2."
      exit 1
    fi
  fi
  download_uv
  uv=$(find_uv) || die "uv was downloaded but is not in ~/.local/bin. Add it to PATH and re-run."
  uv_venv "$uv"
}

python_hint() {
  if [ "$(uname -s)" = Darwin ]; then
    say "Install Python 3.$MIN_MINOR or newer:  brew install python@3.13   (or https://www.python.org/downloads/)"
  elif command -v apt-get >/dev/null 2>&1; then
    say "Install Python 3.$MIN_MINOR or newer:  sudo apt install python3.11 python3.11-venv   (if your release has it)"
  elif command -v dnf >/dev/null 2>&1; then
    say "Install Python 3.$MIN_MINOR or newer:  sudo dnf install python3"
  else
    say "Install Python 3.$MIN_MINOR or newer from your package manager or https://www.python.org/downloads/"
  fi
}

venv_hint() {
  if command -v apt-get >/dev/null 2>&1; then
    say "Install the venv module:  sudo apt install python$1-venv"
  else
    say "Install your distribution's Python venv/ensurepip package for Python $1"
  fi
}

create_venv() {
  if uv=$(find_uv); then
    uv_venv "$uv"
    return 0
  fi
  if py=$(find_python); then
    ver=$(py_version "$py")
    say "Creating .venv with $py (Python $ver) ..."
    if "$py" -m venv .venv >"$LOG" 2>&1; then
      return 0
    fi
    # A failed venv leaves a half-built .venv with no pip; do not keep it.
    rm -rf .venv
    offer_uv "Python $ver is installed, but it cannot create virtual environments (its venv/ensurepip module is missing)." \
      "$(venv_hint "$ver")"
    return 0
  fi
  found=$(py_version python3 || true)
  if [ -n "$found" ]; then
    problem="VulnForge needs Python 3.$MIN_MINOR or newer. This machine's python3 is $found."
  else
    problem="VulnForge needs Python 3.$MIN_MINOR or newer, and no python3 was found."
  fi
  offer_uv "$problem" "$(python_hint)"
}

# --- 1. virtual environment -------------------------------------------------
if [ -e .venv ]; then
  if [ "$RECREATE" = 1 ] || ! venv_usable; then
    if [ ! -f .venv/pyvenv.cfg ] && [ -n "$(ls -A .venv 2>/dev/null)" ]; then
      die ".venv exists but is not a Python virtual environment. Move it aside and re-run."
    fi
    if [ "$RECREATE" = 1 ]; then
      say "Removing .venv (--recreate) ..."
    else
      say "Existing .venv is broken or too old; rebuilding it ..."
    fi
    rm -rf .venv
  else
    say "Using existing .venv (Python $(py_version "$VENV_PY"))."
  fi
fi
[ -e .venv ] || create_venv
venv_usable || die ".venv was created but is not usable. Try: ./install.sh --recreate"

# --- 2. package + dependencies ----------------------------------------------
say "Installing VulnForge and its dependencies (a minute or so the first time) ..."
if uv=$(find_uv); then
  "$uv" pip install --python "$VENV_PY" -e "$SPEC" >"$LOG" 2>&1 || installed=no
else
  PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV_PY" -m pip install -e "$SPEC" >"$LOG" 2>&1 || installed=no
fi
if [ "${installed:-yes}" = no ]; then
  show_log
  die "dependency install failed. Check your network / proxy, then run ./install.sh again."
fi

# --- 3. verify ---------------------------------------------------------------
if ! .venv/bin/vf --help >"$LOG" 2>&1; then
  show_log
  die "installed, but 'vf --help' does not run. Try: ./install.sh --recreate"
fi

say ""
say "VulnForge is installed (Python $(py_version "$VENV_PY"), in .venv)."
say ""
say "  Start the dashboard    ./start.sh                  -> http://127.0.0.1:8787"
say "  Use the CLI            source .venv/bin/activate   then: vf --help"
say "  Try the toy target     vf init --target fixtures/toy_sqli"
say ""
say "Re-run ./install.sh after 'git pull' to pick up new dependencies."
