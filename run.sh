#!/usr/bin/env bash
# run.sh - launch computer-audit (Linux, macOS, Git-Bash/WSL on Windows)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -d venv ]; then
  echo "Virtual env not found. Run ./install.sh first."
  exit 1
fi
# shellcheck disable=SC1091
source venv/bin/activate

CMD="${1:-}"
case "$CMD" in
  iam|forensics|api|audit|web|tui|"")
    python -m cli.main "${@:1}"
    ;;
  *)
    echo "Unknown command: $CMD"
    echo "Usage: ./run.sh [iam|forensics|api|audit|web|tui] [args...]"
    exit 2
    ;;
esac
