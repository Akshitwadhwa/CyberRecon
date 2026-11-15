"""Run the ADK pipeline once and print the session state that agents shared.

Usage:
  python adk_app/agent_session_runner.py case-b
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from adk_app.agent import root_agent  # noqa: E402
from adk_app.callbacks import LifecycleMonitoringPlugin  # noqa: E402
from cyberrecon.guardrails import (  # noqa: E402
    assert_grounded,
    ensure_attack_mapping_section,
    parse_attack_mappings,
)
from cyberrecon.ingest import run as ingest  # noqa: E402
from cyberrecon.a2a_client import invoke_crewai  # noqa: E402
from cyberrecon.store import connect, get_events  # noqa: E402
from cyberrecon.safe_errors import redacted_exception_line  # noqa: E402
from cyberrecon.tracing import get_span_records  # noqa: E402

APP_NAME = "cyberrecon_adk"
USER_ID = "analyst"
STATE_KEYS = (
    "incident_id",
    "crewai_findings",
    "ticket_brief",
    "network_findings",
    "endpoint_findings",
    "identity_findings",
    "reconciliation",
    "incident_report",
)


def _text_from_event(event) -> str:
    content = getattr(event, "content", None)
    parts = getattr(content, "parts", None) or []
    chunks = []
    for part in parts:
        text = getattr(part, "text", None)
        if text:
            chunks.append(text)
    return "\n".join(chunks).strip()


def _append_evidence_trust(incident_id: str, report: str) -> str:
    """Add deterministic trust labels for cited events to the saved report."""
    from cyberrecon.guardrails import cited_event_ids

    cited = cited_event_ids(report)
    if not cited:
        return report
    conn = connect()
    try:
        rows = {row["id"].lower(): row for row in get_events(conn, incident_id)}
    finally:
        conn.close()
    labels = [
        f"- {event_id}: provenance={rows[event_id]['provenance']}; verification_status={rows[event_id]['verification_status']}"
        for event_id in cited
        if event_id in rows
    ]
    if not labels:
        return report
    return report.rstrip() + "\n\n## Evidence trust\n" + "\n".join(labels) + "\n"


def _persist_evaluation_artifact(
    *,
    incident_id: str,
    run_folder: Path,
    monitor: LifecycleMonitoringPlugin,
    started: float,
    span_records: list[dict[str, object]],
    status: str,
) -> Path:
    from cyberrecon.evaluation import build_evaluation_report

    evaluation = build_evaluation_report(
        incident_id=incident_id,
        run_folder=run_folder,
        total_duration_ms=(time.perf_counter() - started) * 1000,
        monitor=monitor,
        span_records=span_records,
        status=status,
    )
    destination = ROOT / "runs" / "evaluations"
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"{incident_id}-{run_folder.name}.json"
    output.write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
    return output


async def run_investigation(
    incident_id: str,
    monitor: LifecycleMonitoringPlugin | None = None,
    validate_outputs: bool = True,
    auto_evaluate: bool = True,
) -> Path:
    started = time.perf_counter()
    monitor = monitor or LifecycleMonitoringPlugin()
    span_start = len(get_span_records())
    folder = ROOT / "runs" / "adk" / incident_id / datetime.now().strftime("%Y%m%d-%H%M%S")
    folder.mkdir(parents=True, exist_ok=True)
    initial_state = {"incident_id": incident_id}
    state = dict(initial_state)
    report = ""
    session_service = None
    session_id = None
    completed = False
    try:
        ingest()
        crewai_a2a_url = os.getenv("CREWAI_A2A_URL", "").strip()
        if crewai_a2a_url:
            findings = invoke_crewai(crewai_a2a_url, incident_id)
            initial_state["crewai_findings"] = findings.model_dump(mode="json")
            state = dict(initial_state)
            print(f"Received CrewAI findings over A2A: {len(findings.evidence)} evidence references")
        session_service = InMemorySessionService()
        session_id = str(uuid.uuid4())
        await session_service.create_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session_id,
            state=initial_state,
        )
        runner = Runner(
            agent=root_agent,
            app_name=APP_NAME,
            session_service=session_service,
            plugins=[monitor],
        )
        message = types.Content(
            role="user",
            parts=[types.Part(text=f"Investigate incident {incident_id}.")],
        )

        print(f"Session {session_id}")
        print(f"Initial state: incident_id={incident_id}")
        for event in runner.run(user_id=USER_ID, session_id=session_id, new_message=message):
            author = getattr(event, "author", None) or "agent"
            text = _text_from_event(event)
            if text and getattr(event, "is_final_response", lambda: False)():
                print(f"\n----- {author} -----")
                print(text)

        session = await session_service.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id
        )
        state = dict(session.state)
        if validate_outputs:
            for specialist_key in ("network_findings", "endpoint_findings"):
                state[specialist_key] = ensure_attack_mapping_section(
                    str(state.get(specialist_key) or "")
                )
                parse_attack_mappings(incident_id, str(state.get(specialist_key) or ""))
        report = str(state.get("incident_report") or "")
        if report and validate_outputs:
            assert_grounded(incident_id, report)
            report = _append_evidence_trust(incident_id, report)
            state["incident_report"] = report

        print("\n========== SESSION STATE ==========")
        for key in STATE_KEYS:
            value = state.get(key, "")
            preview = str(value).replace("\n", " ")
            if len(preview) > 180:
                preview = preview[:180] + "..."
            print(f"{key}: {preview}")
        missing = [key for key in STATE_KEYS if key != "incident_id" and not state.get(key)]
        if missing:
            print("Missing state keys:", ", ".join(missing))
        completed = True
        return folder
    finally:
        if session_service is not None and session_id is not None:
            try:
                session = await session_service.get_session(
                    app_name=APP_NAME, user_id=USER_ID, session_id=session_id
                )
                state = dict(session.state)
            except Exception:
                pass
        if not report:
            report = str(state.get("incident_report") or "")
        (folder / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
        (folder / "incident_report.md").write_text(report, encoding="utf-8")
        if auto_evaluate:
            try:
                _persist_evaluation_artifact(
                    incident_id=incident_id,
                    run_folder=folder,
                    monitor=monitor,
                    span_records=get_span_records()[span_start:],
                    started=started,
                    status="completed" if completed else "failed",
                )
            except Exception:
                # Evaluation must never mask the investigation's original result.
                pass
        if completed:
            print(f"\nSaved state: {folder}")


def main() -> None:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-b"
    try:
        asyncio.run(run_investigation(case_id))
    except Exception as error:
        print(
            "adk_process_error " + redacted_exception_line(error, stage="adk_execution"),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
