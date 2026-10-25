"""Run the ADK pipeline once and print the session state that agents shared.

Usage:
  python adk_app/agent_session_runner.py case-b
"""

from __future__ import annotations

import asyncio
import json
import sys
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
from cyberrecon.guardrails import assert_grounded  # noqa: E402
from cyberrecon.ingest import run as ingest  # noqa: E402

APP_NAME = "cyberrecon_adk"
USER_ID = "analyst"
STATE_KEYS = (
    "incident_id",
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


async def run_investigation(incident_id: str) -> Path:
    ingest()
    session_service = InMemorySessionService()
    session_id = str(uuid.uuid4())
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={"incident_id": incident_id},
    )
    runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)
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
    report = str(state.get("incident_report") or "")
    if report:
        assert_grounded(incident_id, report)

    folder = ROOT / "runs" / "adk" / incident_id / datetime.now().strftime("%Y%m%d-%H%M%S")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (folder / "incident_report.md").write_text(report, encoding="utf-8")

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
    print(f"\nSaved state: {folder}")
    return folder


if __name__ == "__main__":
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-b"
    asyncio.run(run_investigation(case_id))
