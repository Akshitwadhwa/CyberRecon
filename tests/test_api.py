from __future__ import annotations

import json
import logging
import sqlite3
import tempfile
from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi import HTTPException

from cyberrecon.api import app as api_module
from cyberrecon.store import get_events, get_incident, init_db as store_init_db


def _write_artifacts(tmp_path):
    run = tmp_path / "runs" / "adk" / "case-b" / "20261114-202429"
    run.mkdir(parents=True)
    (run / "state.json").write_text(json.dumps({"incident_id": "case-b", "incident_report": "saved"}), encoding="utf-8")
    (run / "incident_report.md").write_text("# Report\nObserved ep-11.", encoding="utf-8")
    evaluation = tmp_path / "runs" / "evaluations"
    evaluation.mkdir(parents=True)
    (evaluation / "case-b-20261114-202430.json").write_text(json.dumps({"schema_version": 1, "timing": {"total_duration_ms": 12}}), encoding="utf-8")
    second_run = tmp_path / "runs" / "adk" / "case-c" / "20261114-202431"
    second_run.mkdir(parents=True)
    (second_run / "state.json").write_text(json.dumps({"incident_id": "case-c", "identity_findings": "Identity-only finding"}), encoding="utf-8")


def test_read_only_artifact_endpoints(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        _write_artifacts(root)
        monkeypatch.setattr(api_module, "RUNS_DIR", root / "runs" / "adk")
        monkeypatch.setattr(api_module, "EVALUATIONS_DIR", root / "runs" / "evaluations")
        assert api_module.list_investigations()[0].incident_id == "case-b"
        assert api_module.get_investigation("case-b")["state"]["incident_id"] == "case-b"
        assert api_module.get_report("case-b")["markdown"].startswith("# Report")
        assert api_module.get_evaluation("case-b")["metrics"]["schema_version"] == 1

        summaries = {item.incident_id: item for item in api_module.list_investigations()}
        assert summaries["case-b"].has_report is True
        assert summaries["case-b"].has_evaluation is True
        assert summaries["case-c"].has_report is False
        assert summaries["case-c"].has_evaluation is False


def test_invalid_or_missing_incidents_are_safe(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        monkeypatch.setattr(api_module, "RUNS_DIR", root / "runs" / "adk")
        monkeypatch.setattr(api_module, "EVALUATIONS_DIR", root / "runs" / "evaluations")
        with pytest.raises(HTTPException) as invalid:
            api_module.get_investigation("../../.env")
        assert invalid.value.status_code == 400
        with pytest.raises(HTTPException) as missing:
            api_module.get_investigation("unknown")
        assert missing.value.status_code == 404
        with pytest.raises(HTTPException) as no_report:
            api_module.get_report("case-b")
        assert no_report.value.status_code == 404


def test_missing_optional_artifacts_are_reported_safely(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        _write_artifacts(root)
        monkeypatch.setattr(api_module, "RUNS_DIR", root / "runs" / "adk")
        monkeypatch.setattr(api_module, "EVALUATIONS_DIR", root / "runs" / "evaluations")
        assert api_module.get_investigation("case-c")["state"]["incident_id"] == "case-c"
        with pytest.raises(HTTPException) as missing_report:
            api_module.get_report("case-c")
        assert missing_report.value.status_code == 404
        with pytest.raises(HTTPException) as missing_evaluation:
            api_module.get_evaluation("case-c")
        assert missing_evaluation.value.status_code == 404


def test_dashboard_auth_rejects_missing_and_invalid_bearer_tokens(monkeypatch):
    monkeypatch.setenv(api_module.API_TOKEN_ENV, "dashboard-test-token")
    with pytest.raises(HTTPException) as missing:
        api_module.require_api_auth(None)
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as invalid:
        api_module.require_api_auth("Bearer wrong-token")
    assert invalid.value.status_code == 401
    assert api_module.require_api_auth("Bearer dashboard-test-token") is None


def test_cors_origins_are_explicit_and_never_wildcard(monkeypatch):
    monkeypatch.setenv(api_module.FRONTEND_ORIGINS_ENV, "https://console.example, *")
    assert api_module._frontend_origins() == ["https://console.example"]


def test_submission_persists_narrative_and_returns_async_job(monkeypatch):
    monkeypatch.delenv(api_module.API_TOKEN_ENV, raising=False)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    monkeypatch.setattr(api_module, "init_db", lambda: store_init_db(connection))

    class InlineExecutor:
        def submit(self, function, *args):
            function(*args)

    monkeypatch.setattr(api_module, "_executor", InlineExecutor())
    monkeypatch.setattr(api_module, "_execute_investigation", lambda _id: Path("20261115-120000"))
    submission = api_module.InvestigationSubmission(
        description="A user opened a suspicious attachment and PowerShell made an outbound connection."
    )
    result = api_module.create_investigation(submission)
    assert result.status == "completed"
    assert result.investigation_id.startswith("submitted-")
    assert api_module.get_investigation_status(result.investigation_id).run_id == "20261115-120000"


def test_submission_rejects_short_or_blank_narratives():
    with pytest.raises(ValueError):
        api_module.InvestigationSubmission(description="too short")


def test_complete_incident_json_is_validated_and_persisted(monkeypatch):
        db_uri = "file:cyberrecon_submission_test?mode=memory&cache=shared"
        keeper = sqlite3.connect(db_uri, uri=True)
        monkeypatch.setattr(api_module, "init_db", lambda: store_init_db(sqlite3.connect(db_uri, uri=True)))

        class InlineExecutor:
            def submit(self, function, *args):
                function(*args)

        monkeypatch.setattr(api_module, "_executor", InlineExecutor())
        monkeypatch.setattr(api_module, "_execute_investigation", lambda _id: Path("20261115-120001"))
        submission = api_module.InvestigationSubmission(
            incident={
                "id": "case-c",
                "title": "Impossible travel",
                "t_start": "2026-09-09T08:00:00",
                "t_end": "2026-09-09T08:20:00",
                "ticket_text": "Identity alert with structured events.",
                "events": [{
                    "id": "id-920",
                    "timestamp": "2026-09-09T08:02:10",
                    "source": "identity",
                    "event_type": "login_success",
                    "payload": {"user": "anish", "method": "password+mfa"},
                }],
            }
        )
        result = api_module.create_investigation(submission)
        assert result.investigation_id.startswith("submitted-")
        assert result.status == "completed"
        connection = sqlite3.connect(db_uri, uri=True)
        connection.row_factory = sqlite3.Row
        assert get_incident(connection, result.investigation_id)["title"] == "Impossible travel"
        events = get_events(connection, result.investigation_id)
        connection.close()
        assert len(events) == 1
        assert events[0]["id"] == "id-920"
        assert events[0]["payload"]["method"] == "password+mfa"
        keeper.close()


def test_complete_incident_json_rejects_duplicate_or_invalid_events():
    base = {
        "id": "case-c",
        "title": "Impossible travel",
        "t_start": "2026-09-09T08:00:00",
        "t_end": "2026-09-09T08:20:00",
        "ticket_text": "Identity alert.",
        "events": [{
            "id": "id-920", "timestamp": "2026-09-09T08:02:10",
            "source": "identity", "event_type": "login_success", "payload": {},
        }],
    }
    with pytest.raises(ValueError, match="event ids must be unique"):
        api_module.InvestigationSubmission(incident={**base, "events": [base["events"][0], base["events"][0]]})
    with pytest.raises(ValueError, match="String should match"):
        api_module.InvestigationSubmission(incident={**base, "events": [{**base["events"][0], "source": "unknown"}]})


def test_complete_incident_json_remaps_existing_event_ids(monkeypatch):
    db_uri = "file:cyberrecon_collision_test?mode=memory&cache=shared"
    keeper = sqlite3.connect(db_uri, uri=True)
    store_init_db(keeper)
    keeper.execute("INSERT INTO incidents (id, title, t_start, t_end, ticket_text) VALUES (?, ?, ?, ?, ?)", ("seed", "Seed", "2026-01-01", "2026-01-01", "seed"))
    keeper.execute(
        "INSERT INTO events (id, incident_id, timestamp, source, event_type, payload) VALUES (?, ?, ?, ?, ?, ?)",
        ("net-920", "seed", "2026-01-01T00:00:00", "network", "connection", "{}"),
    )
    keeper.commit()
    monkeypatch.setattr(api_module, "init_db", lambda: store_init_db(sqlite3.connect(db_uri, uri=True)))

    class InlineExecutor:
        def submit(self, function, *args):
            function(*args)

    monkeypatch.setattr(api_module, "_executor", InlineExecutor())
    monkeypatch.setattr(api_module, "_execute_investigation", lambda _id: Path("20261115-120002"))
    submission = api_module.InvestigationSubmission(incident={
        "id": "case-b", "title": "Copied incident", "t_start": "2026-09-09T10:30:00",
        "t_end": "2026-09-09T10:40:00", "ticket_text": "Copied evidence.",
        "events": [{"id": "net-920", "timestamp": "2026-09-09T10:33:08", "source": "network", "event_type": "connection", "payload": {"dst_port": 443, "_original_event_id": "caller-value"}}],
    })
    result = api_module.create_investigation(submission)
    connection = sqlite3.connect(db_uri, uri=True)
    connection.row_factory = sqlite3.Row
    events = get_events(connection, result.investigation_id)
    connection.close()
    keeper.close()
    assert events[0]["id"] != "net-920"
    assert events[0]["payload"]["_original_event_id"] == "caller-value"
    assert events[0]["payload"]["_original_event_id_2"] == "net-920"


def test_adk_executor_uses_dedicated_venv_and_parses_only_saved_state(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="Saved state: runs/adk/new-id/20261115-120000\n", stderr="adk_event=agent_error error_type=APIConnectionError")

    monkeypatch.setattr(api_module.subprocess, "run", fake_run)
    folder = api_module._execute_investigation("new-id")
    assert folder.as_posix().endswith("runs/adk/new-id/20261115-120000")
    command = calls[0][0]
    assert ".venv-adk" in Path(command[0]).parts
    assert command[1:4] == ["-m", "adk_app.agent_session_runner", "new-id"]
    assert calls[0][1]["capture_output"] is True


def test_adk_executor_logs_nonzero_exit_without_child_output(monkeypatch, caplog):
    monkeypatch.setattr(
        api_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=17, stdout="", stderr="secret prompt"),
    )
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        with pytest.raises(RuntimeError, match="exited with code 17"):
            api_module._execute_investigation("submitted-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "stage=adk_subprocess_exit" in output
    assert "return_code=17" in output
    assert "secret prompt" not in output


def test_adk_executor_logs_missing_saved_state(monkeypatch, caplog):
    monkeypatch.setattr(
        api_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="completed", stderr=""),
    )
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        with pytest.raises(RuntimeError, match="saved state"):
            api_module._execute_investigation("submitted-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "stage=adk_missing_saved_state" in output
    assert "return_code=0" in output


def test_adk_executor_logs_only_allowlisted_child_error_metadata(monkeypatch, caplog):
    stderr = (
        "adk_event=agent_error timestamp=2026-11-15T10:00:00+00:00 "
        "trace_id=abc123 agent=InvestigationCoordinator error_type=APIConnectionError "
        "http_status=503 provider_error_code=temporarily_unavailable request_id=req-1 "
        "prompt=secret incident=case-b authorization=secret"
    )
    monkeypatch.setattr(
        api_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=stderr,
        ),
    )
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        with pytest.raises(RuntimeError):
            api_module._execute_investigation("submitted-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "stage=adk_child_error" in output
    assert "event=agent_error" in output
    assert "error_type=APIConnectionError" in output
    assert "http_status=503" in output
    assert "provider_error_code=temporarily_unavailable" in output
    assert "request_id=req-1" in output
    assert "prompt=" not in output
    assert "incident=" not in output
    assert "authorization=" not in output


def test_adk_executor_forwards_safe_process_error_metadata(monkeypatch, caplog):
    stderr = (
        "adk_process_error stage=adk_execution "
        "exception_types=APIConnectionError>ConnectionError "
        "http_status=503 provider_error_code=temporarily_unavailable request_id=req-safe "
        "\nprompt=secret incident=case-b"
    )
    monkeypatch.setattr(
        api_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr=stderr),
    )
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        with pytest.raises(RuntimeError):
            api_module._execute_investigation("submitted-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "adk_child_error investigation_id=submitted-test" in output
    assert "stage=adk_execution" in output
    assert "exception_types=APIConnectionError>ConnectionError" in output
    assert "http_status=503" in output
    assert "provider_error_code=temporarily_unavailable" in output
    assert "request_id=req-safe" in output
    assert "prompt=" not in output
    assert "incident=" not in output


def test_adk_executor_rejects_malformed_process_error_metadata(monkeypatch, caplog):
    stderr = "adk_process_error stage=adk_execution exception_types=RuntimeError unknown=secret"
    monkeypatch.setattr(
        api_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr=stderr),
    )
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        with pytest.raises(RuntimeError):
            api_module._execute_investigation("submitted-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "unknown=secret" not in output
    assert "adk_child_error investigation_id=submitted-test stage=adk_execution" not in output


def test_api_failure_logging_is_typed_and_redacted(monkeypatch, caplog):
    class ProviderError(RuntimeError):
        status_code = 503
        code = "temporarily_unavailable"
        request_id = "req_safe_test"

    error = ProviderError("secret prompt and authorization header")
    error.__cause__ = ConnectionError("private incident data")
    monkeypatch.setattr(api_module, "_execute_investigation", lambda _id: (_ for _ in ()).throw(error))
    with caplog.at_level(logging.ERROR, logger="cyberrecon.api"):
        api_module._run_investigation_job("safe-test")
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "ProviderError>ConnectionError" in output
    assert "http_status=503" in output
    assert "provider_error_code=temporarily_unavailable" in output
    assert "request_id=req_safe_test" in output
    assert "secret prompt" not in output
    assert "authorization header" not in output
