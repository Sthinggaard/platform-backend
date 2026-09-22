#!/usr/bin/env sh
set -e

# Allow running from any working dir; stash the chosen port for local tooling.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT_CONFIG_FILE="${RISKLENCE_LOCAL_PORT_CONFIG_FILE:-${ROOT}/../config/local-ports.env}"
BFF_ENV_FILE="${BFF_ENV_FILE:-${ROOT}/bff/.env}"
BFF_ENV_LOCAL_FILE="${BFF_ENV_LOCAL_FILE:-${ROOT}/bff/.env.local}"
HOST=${BFF_HOST:-0.0.0.0}
CERT=${BFF_SSL_CERTFILE:-}
KEY=${BFF_SSL_KEYFILE:-}

load_env_file() {
  FILE_PATH="$1"
  if [ -f "${FILE_PATH}" ]; then
    set -a
    # shellcheck disable=SC1090
    . "${FILE_PATH}"
    set +a
  fi
}

# Load BFF-specific env first so local startup does not depend on apps/server/.env.local.
load_env_file "${BFF_ENV_FILE}"
load_env_file "${BFF_ENV_LOCAL_FILE}"
load_env_file "${PORT_CONFIG_FILE}"

if [ -n "${RISKLENCE_LOCAL_API_PORT:-}" ] && [ -z "${BFF_UPSTREAM_BASE:-}" ]; then
  BFF_UPSTREAM_BASE="http://localhost:${RISKLENCE_LOCAL_API_PORT}"
  export BFF_UPSTREAM_BASE
fi

# The BFF imports shared server middleware/config. In local development, default those
# shared settings explicitly so a production-only apps/server/.env.local does not break boot.
: "${ENVIRONMENT:=development}"
export ENVIRONMENT

if [ "${ENVIRONMENT}" = "development" ]; then
  : "${AUTH_JWT_SECRET:=risklence-dev-only-jwt-secret-do-not-use-in-prod}"
  : "${SECRET_KEY:=risklence-dev-only-jwt-secret-do-not-use-in-prod}"
  export AUTH_JWT_SECRET SECRET_KEY

  case "${DEBUG:-}" in
    "" )
      export DEBUG=false
      ;;
    true|false|1|0|yes|no|on|off|TRUE|FALSE|YES|NO|ON|OFF)
      ;;
    * )
      echo "[bff] DEBUG=${DEBUG} is invalid for shared server settings; defaulting to false"
      export DEBUG=false
      ;;
  esac
fi

if [ -n "${RISKLENCE_LOCAL_BFF_PORT:-}" ]; then
  PORT="${RISKLENCE_LOCAL_BFF_PORT}"
elif [ -n "${BFF_PORT}" ]; then
  PORT="${BFF_PORT}"
else
  echo "[bff] No BFF port configured; set RISKLENCE_LOCAL_BFF_PORT in config/local-ports.env."
  exit 1
fi

# Never start a second BFF on an alternate port: clients have one canonical
# gateway URL, and silently falling back creates a running but unused gateway.
if command -v python >/dev/null 2>&1; then
  if ! python - <<'PY' "${PORT}"
import socket, sys
port = int(sys.argv[1])
for family, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.bind((addr, port))
    except OSError:
        sys.exit(1)
    finally:
        try:
            s.close()
        except Exception:
            pass
PY
  then
    echo "[bff] Port ${PORT} is already in use; stop the existing BFF or use the Docker BFF at http://localhost:${RISKLENCE_LOCAL_BFF_PORT:-${PORT}}."
    exit 1
  fi
fi

# Surface the chosen port for tooling (e.g., local dev config).
# Use printf for POSIX portability (BSD /bin/sh may print literal "-n" with echo).
printf "%s" "${PORT}" > "${ROOT}/.bff-port" || true

# Use Poetry from the server directory to run uvicorn
# Change to server dir first to avoid path issues with spaces
cd "${ROOT}/server"
# Ensure repo root is on PYTHONPATH so "bff" package resolves.
export PYTHONPATH="${ROOT}:${PYTHONPATH:-}"

if [ -n "$CERT" ] && [ -n "$KEY" ]; then
  exec poetry run uvicorn bff.app:app --host "${HOST}" --port "${PORT}" --ssl-certfile "${CERT}" --ssl-keyfile "${KEY}"
else
  exec poetry run uvicorn bff.app:app --host "${HOST}" --port "${PORT}"
fi
