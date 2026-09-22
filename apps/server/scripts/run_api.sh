#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

MODE=${1:-dev}
EXTRA="openai"

printf "Ensuring Poetry deps (with %s extra)\n" "$EXTRA"
poetry install --extras "$EXTRA"

case "$MODE" in
  prod)
    printf "Starting production server using Poetry...\n"
    poetry run python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
    ;;
  *)
    printf "Starting dev server using Poetry (reload)...\n"
    poetry run python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
    ;;
esac
