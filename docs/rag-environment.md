# RAG environment

The Phase 4.1 dependencies are isolated in `.venv-rag` and declared in
`requirements-rag.txt`. This environment is separate from `.venv-adk` and
`.venv-crewai` because their OpenTelemetry dependency versions differ.

## Setup

```powershell
python -m venv .venv-rag
.\.venv-rag\Scripts\python.exe -m ensurepip --upgrade --default-pip
.\.venv-rag\Scripts\python.exe -m pip install -r requirements-rag.txt
.\.venv-rag\Scripts\python.exe -m pip check
```

## Sentence Transformer cache

The planned initial model is `sentence-transformers/all-MiniLM-L6-v2`. Keep
the Hugging Face cache outside the repository and reuse it for indexing and
retrieval:

```powershell
$env:HF_HOME = Join-Path $env:LOCALAPPDATA "huggingface"
$env:HF_HUB_CACHE = Join-Path $env:HF_HOME "hub"
$env:TRANSFORMERS_CACHE = Join-Path $env:HF_HOME "transformers"
```

The first embedding run requires network access to download the model. Later
runs reuse the local cache; `HF_HUB_OFFLINE=1` can be set after the model is
confirmed to be present.

