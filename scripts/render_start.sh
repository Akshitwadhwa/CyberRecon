#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src:$ROOT_DIR"
export PYTHONUNBUFFERED="1"
export HF_HOME="${HF_HOME:-$ROOT_DIR/.cache/huggingface}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-$HF_HOME/hub}"
export HF_HUB_OFFLINE="1"
export LITELLM_LOCAL_MODEL_COST_MAP="True"
export CREWAI_A2A_URL="${CREWAI_A2A_URL:-http://127.0.0.1:8765}"
echo "cyberrecon_start root=$ROOT_DIR port=${PORT:-10000} a2a_url=$CREWAI_A2A_URL"

# Agent Card startup alone does not import CrewAI; the A2A adapter imports it
# lazily when the first investigation arrives. Preflight the real dependency
# with a bound so the service never reports ready with a broken CrewAI runtime.
CREWAI_IMPORT_TIMEOUT_SECONDS="${CREWAI_IMPORT_TIMEOUT_SECONDS:-120}"
echo "crewai_import_preflight_start timeout_seconds=$CREWAI_IMPORT_TIMEOUT_SECONDS"
if ! timeout "${CREWAI_IMPORT_TIMEOUT_SECONDS}s" .venv-crewai/bin/python -c "import crewai, litellm" >/dev/null 2>&1; then
  echo "crewai_import_preflight_failed" >&2
  exit 1
fi
echo "crewai_import_preflight_ok"

cleanup() {
  if [[ -n "${API_PID:-}" ]]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  if [[ -n "${CREWAI_PID:-}" ]]; then
    kill "$CREWAI_PID" 2>/dev/null || true
    wait "$CREWAI_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

.venv-crewai/bin/python -m cyberrecon.crewai_a2a >/tmp/cyberrecon-crewai-a2a.log 2>&1 &
CREWAI_PID=$!
echo "crewai_a2a_started pid=$CREWAI_PID"

for attempt in $(seq 1 60); do
  if .venv-adk/bin/python -c "from urllib.request import urlopen; urlopen('${CREWAI_A2A_URL}/.well-known/agent-card.json', timeout=2).read()" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$CREWAI_PID" 2>/dev/null; then
    echo "crewai_a2a_exited_during_startup" >&2
    cat /tmp/cyberrecon-crewai-a2a.log >&2 || true
    exit 1
  fi
  sleep 1
done

if ! .venv-adk/bin/python -c "from urllib.request import urlopen; urlopen('${CREWAI_A2A_URL}/.well-known/agent-card.json', timeout=2).read()" >/dev/null 2>&1; then
  echo "crewai_a2a_agent_card_timeout" >&2
  cat /tmp/cyberrecon-crewai-a2a.log >&2 || true
  exit 1
fi
echo "crewai_a2a_agent_card_ok"

.venv-adk/bin/python -m uvicorn cyberrecon.api.app:app --host 0.0.0.0 --port "${PORT:-10000}" --no-access-log &
API_PID=$!
echo "fastapi_started pid=$API_PID"

# Keep the single Render web service healthy only while both local components
# are alive. A2A is intentionally a child process, so a later crash must not
# leave FastAPI advertising a service that cannot run investigations.
while true; do
  if ! kill -0 "$CREWAI_PID" 2>/dev/null; then
    echo "CrewAI A2A service exited after startup" >&2
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    wait "$API_PID" || true
    exit 1
  fi
  sleep 1
done
