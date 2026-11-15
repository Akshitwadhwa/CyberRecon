#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m venv .venv-adk
python3 -m venv .venv-crewai
python3 -m venv .venv-rag

.venv-adk/bin/python -m pip install -r requirements-adk.txt
.venv-crewai/bin/python -m pip install -r requirements-crewai.txt
.venv-rag/bin/python -m pip install -r requirements-rag.txt

# Fail the build if the CrewAI runtime cannot import on the target Linux image.
# LiteLLM's local map avoids a network fetch during framework initialization.
LITELLM_LOCAL_MODEL_COST_MAP=True .venv-crewai/bin/python -c "import crewai, litellm; print('CrewAI imports verified')"

export PYTHONPATH="$ROOT_DIR/src:$ROOT_DIR"
export HF_HOME="${HF_HOME:-$ROOT_DIR/.cache/huggingface}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-$HF_HOME/hub}"
mkdir -p "$HF_HUB_CACHE"

# Recreate the local SQLite seed database and MITRE index from repository data.
.venv-adk/bin/python main.py ingest
.venv-rag/bin/python scripts/build_mitre_index.py

.venv-adk/bin/python -m pip check
.venv-crewai/bin/python -m pip check
.venv-rag/bin/python -m pip check
