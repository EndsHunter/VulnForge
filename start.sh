#!/bin/sh
# Start the VulnForge dashboard (Linux / macOS). Windows: use start.ps1.
# Installs first if needed. Extra arguments go to `vf dashboard`:
#
#   ./start.sh                 -> http://127.0.0.1:8787
#   ./start.sh --port 8788
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

if [ ! -x .venv/bin/vf ]; then
  echo "VulnForge is not installed yet; running ./install.sh first."
  sh ./install.sh
  echo
fi

exec .venv/bin/vf dashboard "$@"
