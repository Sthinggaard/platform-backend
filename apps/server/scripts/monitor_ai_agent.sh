#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

LOG_FILE=${1:-uvicorn.log}
if [[ ! -f "$LOG_FILE" ]]; then
  echo "Log file $LOG_FILE not found" >&2
  exit 1
fi

printf "Tailing %s for AI agent logs...\n" "$LOG_FILE"
STD_CMD=$(command -v stdbuf || true)
TAIL_CMD="tail -n 20 -f '$LOG_FILE'"
if [[ -n "$STD_CMD" ]]; then
  exec tail -n 20 -f "$LOG_FILE" | stdbuf -oL grep --line-buffered -E 'ai_agent|openai_agent_initialized|ai_agent_not_configured'
else
  exec tail -n 20 -f "$LOG_FILE" | grep -E 'ai_agent|openai_agent_initialized|ai_agent_not_configured'
fi
