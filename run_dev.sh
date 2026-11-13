#!/usr/bin/env bash
# Start SecureMailScope (backend :8000, frontend :5173). Override ports with API_PORT / WEB_PORT.
set -euo pipefail
cd "$(dirname "$0")"
API_PORT="${API_PORT:-8000}"
command -v tshark >/dev/null || echo "WARNING: tshark not found. Install Wireshark/TShark (e.g. 'sudo apt install tshark' or 'sudo pacman -S wireshark-cli'); analysis will be disabled."

if [ ! -d backend/.venv ]; then
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install -r backend/requirements.txt -r backend/requirements-dev.txt
fi
[ -d frontend/node_modules ] || (cd frontend && npm install)

if ss -ltn 2>/dev/null | grep -q ":${API_PORT} "; then
  echo "ERROR: port ${API_PORT} is already in use. Re-run with API_PORT=<free port>." >&2; exit 1
fi

trap 'kill 0' EXIT
(cd backend && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$API_PORT") &
(cd frontend && SMS_API_URL="http://localhost:${API_PORT}" npm run dev) &
echo "UI:      http://localhost:5173"
echo "API:     http://localhost:${API_PORT}   (docs: /docs)"
wait
