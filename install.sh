#!/usr/bin/env bash
# install.sh - cross-platform setup (Linux, macOS, Git-Bash/WSL on Windows)
# Creates a Python venv, installs deps, optional npm install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[computer-audit] Creating Python virtual environment..."
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo "[computer-audit] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

if command -v npm >/dev/null 2>&1; then
  echo "[computer-audit] npm detected; installing frontend deps (optional)..."
  npm install || echo "npm install skipped/failed - frontend not required to run"
else
  echo "[computer-audit] npm not found; skipping frontend (install Node later if needed)"
fi

echo "[computer-audit] Setup complete. Run: ./run.sh"
