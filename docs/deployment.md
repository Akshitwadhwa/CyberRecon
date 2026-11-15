# CyberRecon deployment plan

This is an inspection-based deployment plan for the current repository. It does not deploy resources, add cloud dependencies, or change application behavior.

## Current architecture

The current runtime topology is:

```text
Browser
  -> React/Vite static dashboard
  -> FastAPI read-only dashboard API
       -> runs/adk and runs/evaluations artifacts

ADK worker
  -> Google ADK sequential workflow
  -> local MCP subprocess over stdio
       -> SQLite evidence/IOC store
       -> local MITRE STIX catalog
       -> persistent ChromaDB + Sentence Transformers model
  -> HTTP A2A client
       -> CrewAI A2A service
            -> six-agent CrewAI investigation
            -> SQLite/local fixtures
            -> CrewAI run artifacts
```

MCP is currently not a network service. ADK creates an `McpToolset` with `StdioServerParameters` and launches `python -m cyberrecon.mcp_server` as a child process. A2A is the network boundary between ADK and CrewAI.

### Components and entry points

| Component | Current entry point | Responsibility |
| --- | --- | --- |
| Dashboard | Vite `npm run dev` / built static assets | Browser UI for saved investigations |
| Dashboard API | `python -m cyberrecon.api` | Artifact and investigation-job API, port 8000 |
| ADK workflow | `python main.py adk <incident_id>` | Orchestrates investigation and writes `runs/adk/<id>/<timestamp>/` |
| CrewAI service | `python -m cyberrecon.crewai_a2a` | HTTP A2A server, port 8765 |
| MCP server | `python -m cyberrecon.mcp_server` | Stdio child process exposing seven read-only tools |
| CrewAI CLI | `python main.py investigate <incident_id>` | Standalone six-agent path |
| Ingestion | `python main.py ingest` | Loads JSON incidents and local IOC data into SQLite |
| RAG indexing | `python scripts/build_mitre_index.py` | Offline index-build operation |
| Evaluation | `python scripts/evaluate_case_b.py` | Offline evaluation artifact generation |

The dashboard API reads the latest timestamped ADK run for each incident. It
also accepts validated narrative submissions and launches the existing ADK
workflow in a background worker. It does not convert prose into evidence
events. API authentication is controlled by `CYBERRECON_API_TOKEN`.

## Runtime dependencies and isolation

The selected framework versions require separate environments:

- ADK: `.venv-adk`, `google-adk==2.13.0`, `litellm==1.106.4`, `mcp==2.3.0`, OpenTelemetry 1.44.0.
- CrewAI: `.venv-crewai`, `crewai==1.15.30`, `litellm==1.106.4`, OpenTelemetry 1.45.1.
- RAG: `.venv-rag`, `sentence-transformers==5.1.2`, `chromadb==1.5.9`, `mcp==2.3.0`, OpenTelemetry 1.45.2.
- API/shared profile: FastAPI 0.162.0, Uvicorn 0.54.0, Pydantic 2.12.5.
- Frontend: React 18, Vite, Tailwind CSS and `lucide-react`.

The deployment equivalent is separate container images, not one image that installs every profile. The API image uses the shared profile. The CrewAI image uses the CrewAI profile. The ADK image uses the ADK profile and must also be able to launch the MCP runtime. Because the MCP server imports RAG retrieval code, the ADK/MCP image must include the tested RAG runtime dependencies, or MCP must later be packaged as a separately designed service. Do not mix incompatible profiles without testing.

## Recommended deployment architecture

Use four deployable units plus persistent storage:

1. **Frontend static site**
   - Run `npm run build` in `frontend/`.
   - Serve `frontend/dist/` from object storage/CDN or a static web server.
   - Set build-time `VITE_API_BASE_URL` to the dashboard API URL.

2. **Dashboard API service**
   - Run Uvicorn behind an HTTPS ingress.
   - Mount `runs/adk/` and `runs/evaluations/` read-only where possible.
   - Do not give this service LLM credentials or permission to start investigations.

3. **CrewAI A2A service**
   - Run `python -m cyberrecon.crewai_a2a` in the CrewAI image.
   - Keep it private; only ADK workers should reach it.
   - Mount incident/IOC data and the SQLite database needed by CrewAI tools.
   - Persist CrewAI run artifacts if audit history is required.

4. **ADK investigation worker**
   - Run `python main.py adk <incident_id>` as a bounded job/worker, not a permanent web server.
   - Set `CREWAI_A2A_URL` to the private CrewAI service URL.
   - The worker launches MCP locally over stdio and must reap it on completion, cancellation and failure.
   - Mount writable storage for ADK runs and the SQLite store when ingestion is part of the job.

The API and frontend can be long-running services. ADK and CrewAI should remain separate because they have different dependency profiles and scaling characteristics. A queue can be added later if investigations become user-triggered; this phase does not add a trigger contract.

### Estimated services

The minimum practical layout is **four deployable services/jobs**:

- one static frontend host;
- one FastAPI API service;
- one CrewAI A2A service;
- one ADK worker image/job type.

MCP is currently a per-ADK-worker subprocess, not a fifth service. SQLite, ChromaDB, the model cache and run artifacts are storage resources/volumes.

## Startup commands

All Python commands assume the repository root is the working directory and `PYTHONPATH` includes the required modules:

```powershell
# Dashboard API
$env:PYTHONPATH = "$PWD\src;$PWD"
python -m cyberrecon.api

# CrewAI A2A service, in the CrewAI environment
$env:PYTHONPATH = "$PWD\src"
python -m cyberrecon.crewai_a2a

# ADK worker, in the ADK environment
$env:PYTHONPATH = "$PWD\src;$PWD"
$env:CREWAI_A2A_URL = "http://crewai-a2a:8765"
python main.py adk case-b

# Offline preparation, run separately from request-serving containers
$env:PYTHONPATH = "$PWD\src"
python scripts/build_mitre_index.py
python main.py ingest
```

The current API binds to `127.0.0.1:8000`, and A2A defaults to `127.0.0.1:8765`. A production deployment will need deployment-specific bind/entrypoint configuration so intended peers can connect. That is a later deployment change, not implemented here.

## Environment variables and secret management

Current configuration uses:

- `OPENAI_API_KEY`: required by ADK LiteLLM and CrewAI. Inject only through a platform secret manager.
- `LLM_MODEL`: optional model name; defaults to `gpt-4o-mini`.
- `CREWAI_A2A_URL`: ADK URL for the private CrewAI service.
- `CREWAI_A2A_TIMEOUT_SECONDS`: optional long-running A2A read timeout.
- `CYBERRECON_MCP_TIMEOUT_SECONDS`: optional MCP connection timeout.
- `HF_HOME`, `HF_HUB_CACHE`, `TRANSFORMERS_CACHE`: Sentence Transformers cache locations.
- `HF_HUB_OFFLINE`: use only after the model is already cached.
- `VITE_API_BASE_URL`: frontend build-time API origin; not a secret.
- `CYBERRECON_API_TOKEN`: optional bearer token required by dashboard API
  endpoints when configured. For production, prefer an identity-aware gateway
  so a browser does not receive a shared service token.
- `CYBERRECON_A2A_TOKEN`: bearer token required by the CrewAI A2A POST endpoint
  when configured. Set the same secret only in the ADK worker and CrewAI
  service.
- `CYBERRECON_FRONTEND_ORIGINS`: comma-separated exact frontend origins for
  CORS. Wildcard origins are ignored.

Requirements:

- Use a cloud secret manager or orchestrator secret store for API keys.
- Grant the OpenAI key only to ADK and CrewAI workloads; the API and frontend do not need it.
- Never put secrets in `runs/`, SQLite, Chroma metadata, logs, traces or the frontend bundle.
- Rotate the key independently of images and restrict outbound access to the model provider and required internal services.
- Keep `.env` outside version control; `.env.example` contains placeholders only.
- Set `CYBERRECON_API_TOKEN` and `CYBERRECON_A2A_TOKEN` in deployment secret
  management. Local development may leave them unset, which preserves the
  existing localhost workflow; deployed environments should set them.

## Persistent storage

| Path | Contents | Deployment requirement |
| --- | --- | --- |
| `db/cyberrecon.db` | SQLite incidents, events and IOC snapshot | Writable by ingestion/worker; avoid concurrent writers across replicas |
| `data/incidents/` | Local incident fixtures | Read-only image data or mounted dataset |
| `data/intel/iocs.json` | Local IOC snapshot | Read-only image data or mounted dataset |
| `data/mitre/enterprise-attack.json` | Enterprise ATT&CK STIX dataset | Read-only, versioned with the index |
| `data/rag/chroma/` | Persistent ChromaDB index | Durable volume/artifact; one builder at a time |
| `data/rag/manifest.json` | Index provenance and dimensions | Must match dataset and model |
| Hugging Face cache | `all-MiniLM-L6-v2` files | Durable cache or pre-baked image layer |
| `runs/adk/` | ADK session state and reports | Durable storage shared with API |
| `runs/evaluations/` | Evaluation JSON | Durable storage readable by API |
| `runs/<incident>/` | CrewAI run artifacts | Durable if audit history is required |

The current `ingest()` path performs replacements and is appropriate for one worker/job, not multiple concurrent writers sharing a network filesystem. ChromaDB should be built once and treated as stable during investigations. Start with one writer and explicit volumes before horizontal scaling.

Recommended initial storage layout:

- bake immutable JSON fixtures and the ATT&CK dataset into versioned images or mount them read-only;
- build ChromaDB in a controlled job and publish the resulting index as a versioned artifact/volume;
- use durable storage for run artifacts with retention and access policies;
- back up SQLite if the local evidence store is operationally important.

## Networking

- Expose only the frontend and dashboard API through public HTTPS ingress.
- Keep CrewAI A2A private and allow inbound traffic only from the ADK worker identity.
- Keep MCP on local stdio; do not expose it as public TCP.
- Permit outbound HTTPS from ADK/CrewAI only to the configured model provider and image/model download endpoints during preparation.
- Enforce TLS at the public ingress.
- If A2A ever crosses hosts, use an authenticated encrypted service-to-service channel; the current service supports a shared bearer token but still needs private networking and TLS.
- Update the current localhost-only CORS allowlist for the production dashboard origin as a deliberate later change.

## Security and operational risks

1. **API authentication is token-based:** configure `CYBERRECON_API_TOKEN`, and
   place the API behind an identity-aware gateway for browser-facing production
   use rather than exposing a shared bearer token to the frontend.
2. **A2A authentication is token-based:** configure `CYBERRECON_A2A_TOKEN` on
   both ADK and CrewAI and still restrict the service to the private network.
3. **Artifact sensitivity:** session state and reports may contain incident details. Use encrypted storage, least privilege, retention and redacted logs.
4. **LLM provider dependency:** live investigations need a valid key and outbound network access. Provider failures can leave partial runs.
5. **Long-running A2A calls:** align ingress, worker, client and server timeouts. Do not add automatic retries that duplicate investigations.
6. **Dependency conflicts:** combining ADK and CrewAI can recreate the OpenTelemetry conflict. Keep images isolated and run `pip check`/imports in CI.
7. **Local state and scaling:** SQLite, ChromaDB and filesystem artifacts are not designed for unrestricted multi-replica writes.
8. **MCP lifecycle:** the ADK worker must clean up the child MCP process on success, cancellation and error.
9. **Cold model cache:** prebuild or mount the embedding cache and verify offline retrieval before disabling egress.

## Rollout sequence

1. Build separate API, ADK, CrewAI and RAG/MCP images from the existing profiles.
2. Run `pip check`, imports, MCP stdio checks and regression tests in CI for each image.
3. Build the MITRE index from the pinned dataset and verify its manifest before publishing it.
4. Deploy CrewAI privately and verify its Agent Card and mocked contract request.
5. Run one ADK worker with secret injection, durable output and MCP cleanup checks.
6. Deploy the read-only API against persisted artifacts and test path validation/missing-artifact behavior.
7. Publish the frontend with the API origin configured and validate desktop/mobile ingress access.
8. Add identity-based authentication, centralized logs, backups and scaling only as separate reviewed changes; the current submission token is a transitional control.

## Open decisions before production

- Keep MCP as an ADK-local stdio process or design a separately packaged internal service.
- Keep run artifacts on durable filesystem or move them behind an object-storage repository.
- Decide whether SQLite meets concurrency and retention requirements.
- Choose the identity gateway and service identity for A2A authorization.
- Define how jobs are submitted and tracked; the current API is deliberately read-only.

