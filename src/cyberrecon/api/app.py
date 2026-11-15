from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import logging
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Path as ApiPath
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyberrecon.store import get_incident, ingest_incident, init_db
from cyberrecon.safe_errors import exception_metadata

ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "runs" / "adk"
EVALUATIONS_DIR = ROOT / "runs" / "evaluations"
INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{8}-\d{6}$")
API_TOKEN_ENV = "CYBERRECON_API_TOKEN"
FRONTEND_ORIGINS_ENV = "CYBERRECON_FRONTEND_ORIGINS"
JOB_STATUSES = {"pending", "running", "completed", "failed"}
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cyberrecon-investigation")
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()
LOGGER = logging.getLogger("cyberrecon.api")
_SAFE_CHILD_EVENT_VALUE = re.compile(r"^[A-Za-z0-9_.:+/\-]{1,128}$")
_CHILD_EVENT_FIELDS = {
    "timestamp",
    "trace_id",
    "agent",
    "tool",
    "duration_ms",
    "status",
    "error_type",
    "exception_types",
    "http_status",
    "provider_error_code",
    "request_id",
}
_PROCESS_ERROR_FIELDS = {"stage", *_CHILD_EVENT_FIELDS - {"timestamp", "trace_id", "agent", "tool", "duration_ms", "status"}}
_SAFE_EXCEPTION_TYPES = re.compile(r"^[A-Za-z0-9_.:>+\-/]{1,256}$")


def _frontend_origins() -> list[str]:
    raw = os.getenv(FRONTEND_ORIGINS_ENV, "").strip()
    origins = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    if not origins:
        origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
    return [origin for origin in origins if origin != "*"]


def require_api_auth(authorization: str | None = Header(default=None)) -> None:
    """Require a configured bearer token; unset keeps local development usable."""
    expected = os.getenv(API_TOKEN_ENV, "").strip()
    if not expected:
        return
    supplied = authorization or ""
    prefix = "Bearer "
    if not supplied.startswith(prefix) or not hmac.compare_digest(supplied[len(prefix):], expected):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvestigationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    latest_run: str | None = None
    has_state: bool
    has_report: bool
    has_evaluation: bool


class IncidentEventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^(?:id|ep|net|al)-\d+$")
    timestamp: str = Field(min_length=1, max_length=64)
    source: str = Field(pattern=r"^(?:network|endpoint|identity|alert_image)$")
    event_type: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    provenance: Literal["user_submitted"] = "user_submitted"
    verification_status: Literal["unverified"] = "unverified"

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_iso8601(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 value") from exc
        return value


class IncidentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    t_start: str = Field(min_length=1, max_length=64)
    t_end: str = Field(min_length=1, max_length=64)
    ticket_text: str = Field(min_length=1, max_length=20_000)
    events: list[IncidentEventInput] = Field(max_length=10_000)
    provenance: Literal["user_submitted"] = "user_submitted"
    verification_status: Literal["unverified"] = "unverified"

    @field_validator("t_start", "t_end")
    @classmethod
    def incident_time_is_iso8601(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("incident times must be ISO-8601 values") from exc
        return value

    @field_validator("events")
    @classmethod
    def event_ids_are_unique(cls, value: list[IncidentEventInput]) -> list[IncidentEventInput]:
        ids = [event.id for event in value]
        if len(ids) != len(set(ids)):
            raise ValueError("event ids must be unique within an incident")
        return value


class InvestigationSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, min_length=20, max_length=20_000)
    incident: IncidentInput | None = None

    @field_validator("description")
    @classmethod
    def description_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("description must not be blank")
        return value

    @model_validator(mode="after")
    def require_description_or_incident(self) -> "InvestigationSubmission":
        if self.description is None and self.incident is None:
            raise ValueError("provide either description or incident JSON")
        if self.description is not None and self.incident is not None:
            raise ValueError("provide description or incident JSON, not both")
        return self


class InvestigationJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    status: str
    run_id: str | None = None
    error: str | None = None


app = FastAPI(title="CyberRecon Dashboard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def _validate_incident_id(incident_id: str) -> str:
    if not INCIDENT_ID_PATTERN.fullmatch(incident_id):
        raise HTTPException(status_code=400, detail="Invalid incident id")
    return incident_id


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _set_job(investigation_id: str, **updates: Any) -> None:
    with _jobs_lock:
        _jobs.setdefault(investigation_id, {"investigation_id": investigation_id}).update(updates)


def _adk_interpreter() -> Path:
    """Return the dedicated ADK interpreter; never fall back to shared `.venv`."""
    relative = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    interpreter = ROOT / ".venv-adk" / relative
    if not interpreter.is_file():
        raise RuntimeError("Dedicated .venv-adk interpreter is unavailable")
    return interpreter


def _safe_investigation_id(value: str) -> str:
    return value if INCIDENT_ID_PATTERN.fullmatch(value) else "redacted"


def _redacted_child_event(line: str) -> str | None:
    """Return only allowlisted ADK event metadata; never forward raw child output."""
    tokens = line.split()
    if not tokens or not tokens[0].startswith("adk_event="):
        return None
    event = tokens[0].split("=", 1)[1]
    if not _SAFE_CHILD_EVENT_VALUE.fullmatch(event):
        return None
    fields = [f"event={event}"]
    for token in tokens[1:]:
        key, separator, value = token.partition("=")
        if separator and key in _CHILD_EVENT_FIELDS and _SAFE_CHILD_EVENT_VALUE.fullmatch(value):
            fields.append(f"{key}={value}")
    return " ".join(fields)


def _redacted_child_process_error(line: str) -> str | None:
    """Strictly parse the runner's safe process-error record."""
    tokens = line.split()
    if not tokens or tokens[0] != "adk_process_error":
        return None
    fields: dict[str, str] = {}
    for token in tokens[1:]:
        key, separator, value = token.partition("=")
        if not separator or key not in _PROCESS_ERROR_FIELDS:
            return None
        value_pattern = _SAFE_EXCEPTION_TYPES if key == "exception_types" else _SAFE_CHILD_EVENT_VALUE
        if key in fields or not value_pattern.fullmatch(value):
            return None
        fields[key] = value
    required = {"stage", "exception_types", "http_status", "provider_error_code", "request_id"}
    if set(fields) != required:
        return None
    return " ".join(f"{key}={fields[key]}" for key in ("stage", "exception_types", "http_status", "provider_error_code", "request_id"))


def _execute_investigation(investigation_id: str) -> Path:
    """Run the unchanged ADK workflow in its isolated interpreter."""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
    result = subprocess.run(
        [str(_adk_interpreter()), "-m", "adk_app.agent_session_runner", investigation_id],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    safe_id = _safe_investigation_id(investigation_id)
    for line in result.stderr.splitlines():
        process_error = _redacted_child_process_error(line)
        if process_error:
            LOGGER.error(
                "adk_child_error investigation_id=%s %s",
                safe_id,
                process_error,
            )
            continue
        event = _redacted_child_event(line)
        if event and event.split(" ", 1)[0] in {"event=agent_error", "event=tool_error", "event=run_error"}:
            LOGGER.error(
                "adk_child_error investigation_id=%s stage=adk_child_error %s",
                safe_id,
                event,
            )
    if result.returncode != 0:
        LOGGER.error(
            "adk_subprocess_exit investigation_id=%s stage=adk_subprocess_exit return_code=%s",
            safe_id,
            result.returncode,
        )
        raise RuntimeError(f"ADK subprocess exited with code {result.returncode}")
    matches = re.findall(r"(?m)^Saved state: (.+)$", result.stdout)
    if not matches:
        LOGGER.error(
            "adk_missing_saved_state investigation_id=%s stage=adk_missing_saved_state return_code=%s",
            safe_id,
            result.returncode,
        )
        raise RuntimeError("ADK subprocess completed without a saved state path")
    LOGGER.info(
        "adk_subprocess_exit investigation_id=%s stage=adk_subprocess_exit return_code=%s",
        safe_id,
        result.returncode,
    )
    return Path(matches[-1].strip())


def _run_investigation_job(investigation_id: str) -> None:
    _set_job(investigation_id, status="running")
    try:
        folder = _execute_investigation(investigation_id)
    except Exception as error:
        # Do not expose provider errors, prompts, paths, or credentials through the API.
        LOGGER.error("investigation_failed %s", " ".join(f"{key}={value}" for key, value in exception_metadata(error).items()))
        _set_job(investigation_id, status="failed", error="Investigation failed")
        return
    _set_job(investigation_id, status="completed", run_id=folder.name, error=None)


def _job_for(investigation_id: str) -> InvestigationJob:
    with _jobs_lock:
        job = dict(_jobs.get(investigation_id, {}))
    if job:
        return InvestigationJob(**job)
    runs = _run_dirs(investigation_id)
    if runs:
        return InvestigationJob(
            investigation_id=investigation_id,
            status="completed",
            run_id=runs[0].name,
        )
    raise HTTPException(status_code=404, detail="Investigation not found")


def _persist_submitted_incident(
    investigation_id: str,
    submission: InvestigationSubmission,
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    if submission.incident is not None:
        incident = submission.incident.model_dump(mode="json")
        incident["id"] = investigation_id
    else:
        incident = {
            "id": investigation_id,
            "title": "Submitted incident narrative",
            "t_start": now,
            "t_end": now,
            "ticket_text": submission.description,
            "events": [],
        }
    conn = init_db()
    try:
        if get_incident(conn, investigation_id):
            raise HTTPException(status_code=409, detail="Investigation id already exists")
        existing = {row[0] for row in conn.execute("SELECT id FROM events").fetchall()}
        used = set(existing)
        prefixes = {"identity": "id", "endpoint": "ep", "network": "net", "alert_image": "al"}
        for event in incident["events"]:
            original_id = event["id"]
            if original_id not in used:
                used.add(original_id)
                continue
            digest = hashlib.sha256(f"{investigation_id}:{original_id}".encode("utf-8")).hexdigest()
            suffix = int(digest[:12], 16) % 1_000_000_000_000
            prefix = prefixes[event["source"]]
            candidate = f"{prefix}-{suffix:012d}"
            while candidate in used or conn.execute("SELECT 1 FROM events WHERE id = ?", (candidate,)).fetchone():
                suffix = (suffix + 1) % 1_000_000_000_000
                candidate = f"{prefix}-{suffix:012d}"
            event["id"] = candidate
            metadata_key = "_original_event_id"
            suffix_number = 1
            while metadata_key in event["payload"]:
                suffix_number += 1
                metadata_key = f"_original_event_id_{suffix_number}"
            event["payload"] = {**event["payload"], metadata_key: original_id}
            used.add(candidate)
        ingest_incident(conn, incident)
        conn.commit()
    finally:
        conn.close()


def _run_dirs(incident_id: str) -> list[Path]:
    incident_dir = RUNS_DIR / incident_id
    if incident_dir.is_symlink() or not _inside(RUNS_DIR, incident_dir) or not incident_dir.is_dir():
        return []
    return sorted(
        (
            path
            for path in incident_dir.iterdir()
            if not path.is_symlink()
            and _inside(RUNS_DIR, path)
            and path.is_dir()
            and TIMESTAMP_PATTERN.fullmatch(path.name)
        ),
        key=lambda path: path.name,
        reverse=True,
    )


def _evaluation_files(incident_id: str) -> list[Path]:
    if not EVALUATIONS_DIR.is_dir():
        return []
    return sorted(
        (
            path
            for path in EVALUATIONS_DIR.glob(f"{incident_id}-*.json")
            if not path.is_symlink() and _inside(EVALUATIONS_DIR, path) and path.is_file()
        ),
        key=lambda path: path.name,
        reverse=True,
    )


def _evaluation_for_run(incident_id: str, run: Path) -> Path | None:
    """Find metrics explicitly linked to the selected run, never another run."""
    expected_name = f"{incident_id}-{run.name}.json"
    for path in _evaluation_files(incident_id):
        if path.name == expected_name:
            return path
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if payload.get("run_id") == run.name:
            return path
        run_folder = payload.get("run_folder")
        if isinstance(run_folder, str) and Path(run_folder).name == run.name:
            return path
    return None


def _latest_run(incident_id: str) -> Path:
    runs = _run_dirs(incident_id)
    if not runs:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return runs[0]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Investigation artifact is unavailable") from exc


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/investigations", response_model=list[InvestigationSummary], dependencies=[Depends(require_api_auth)])
def list_investigations() -> list[InvestigationSummary]:
    if not RUNS_DIR.is_dir():
        return []
    summaries: list[InvestigationSummary] = []
    for directory in sorted((path for path in RUNS_DIR.iterdir() if path.is_dir()), key=lambda path: path.name):
        incident_id = directory.name
        if not INCIDENT_ID_PATTERN.fullmatch(incident_id):
            continue
        runs = _run_dirs(incident_id)
        evaluations = _evaluation_files(incident_id)
        latest = runs[0] if runs else None
        summaries.append(
            InvestigationSummary(
                incident_id=incident_id,
                latest_run=latest.name if latest else None,
                has_state=bool(latest and (latest / "state.json").is_file()),
                has_report=bool(latest and (latest / "incident_report.md").is_file()),
                has_evaluation=bool(latest and _evaluation_for_run(incident_id, latest)),
            )
        )
    return summaries


@app.post("/api/investigations", response_model=InvestigationJob, status_code=202, dependencies=[Depends(require_api_auth)])
def create_investigation(submission: InvestigationSubmission) -> InvestigationJob:
    investigation_id = f"submitted-{uuid.uuid4().hex}"
    _persist_submitted_incident(investigation_id, submission)
    _set_job(investigation_id, status="pending", run_id=None, error=None)
    _executor.submit(_run_investigation_job, investigation_id)
    return _job_for(investigation_id)


@app.get("/api/investigations/{incident_id}/status", response_model=InvestigationJob, dependencies=[Depends(require_api_auth)])
def get_investigation_status(
    incident_id: str = ApiPath(..., pattern=INCIDENT_ID_PATTERN.pattern),
) -> InvestigationJob:
    return _job_for(_validate_incident_id(incident_id))


@app.get("/api/investigations/{incident_id}", dependencies=[Depends(require_api_auth)])
def get_investigation(
    incident_id: str = ApiPath(..., pattern=INCIDENT_ID_PATTERN.pattern),
) -> dict[str, Any]:
    incident_id = _validate_incident_id(incident_id)
    run = _latest_run(incident_id)
    state_path = run / "state.json"
    if state_path.is_symlink() or not _inside(run, state_path) or not state_path.is_file():
        raise HTTPException(status_code=404, detail="Session state not found")
    return {"incident_id": incident_id, "run_id": run.name, "state": _read_json(state_path)}


@app.get("/api/investigations/{incident_id}/result", dependencies=[Depends(require_api_auth)])
def get_investigation_result(
    incident_id: str = ApiPath(..., pattern=INCIDENT_ID_PATTERN.pattern),
) -> dict[str, Any]:
    return get_investigation(incident_id)


@app.get("/api/investigations/{incident_id}/report", dependencies=[Depends(require_api_auth)])
def get_report(
    incident_id: str = ApiPath(..., pattern=INCIDENT_ID_PATTERN.pattern),
) -> dict[str, str]:
    incident_id = _validate_incident_id(incident_id)
    run = _latest_run(incident_id)
    report_path = run / "incident_report.md"
    if report_path.is_symlink() or not _inside(run, report_path) or not report_path.is_file():
        raise HTTPException(status_code=404, detail="Incident report not found")
    try:
        report = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Incident report is unavailable") from exc
    return {"incident_id": incident_id, "run_id": run.name, "markdown": report}


@app.get("/api/investigations/{incident_id}/evaluation", dependencies=[Depends(require_api_auth)])
def get_evaluation(
    incident_id: str = ApiPath(..., pattern=INCIDENT_ID_PATTERN.pattern),
) -> dict[str, Any]:
    incident_id = _validate_incident_id(incident_id)
    run = _latest_run(incident_id)
    evaluation = _evaluation_for_run(incident_id, run)
    if evaluation is None:
        raise HTTPException(status_code=404, detail="Evaluation metrics not found")
    return {"incident_id": incident_id, "run_id": run.name, "metrics": _read_json(evaluation)}
