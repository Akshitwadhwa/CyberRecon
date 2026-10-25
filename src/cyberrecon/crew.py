"""CrewAI investigation crew. Run after ingest. Needs OPENAI_API_KEY."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from crewai import LLM, Agent, Crew, Process, Task
from dotenv import load_dotenv

from cyberrecon.guardrails import assert_grounded
from cyberrecon.tools import GetEventsTool, GetIntelTool, GetTicketTool

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "runs"

TASK_FILES = (
    "01_coordinator.md",
    "02_network.md",
    "03_endpoint.md",
    "04_identity.md",
    "05_reconciler.md",
    "06_report.md",
)


def _llm() -> LLM:
    load_dotenv(ROOT / ".env")
    load_dotenv(ROOT.parent / ".env")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("Add OPENAI_API_KEY to Project/.env (see .env.example)")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    return LLM(model=model, api_key=api_key, temperature=0.2)


def build_crew() -> Crew:
    llm = _llm()
    events_tool = GetEventsTool()
    intel_tool = GetIntelTool()
    ticket_tool = GetTicketTool()

    coordinator = Agent(
        role="Investigation Coordinator",
        goal="Read the ticket and assign evidence sources without inventing facts.",
        backstory="You run a small SOC investigation desk. You only use ticket text from the tool.",
        tools=[ticket_tool],
        llm=llm,
        verbose=True,
    )
    network_agent = Agent(
        role="Network Analyst",
        goal="Describe network evidence using GetEventsTool with source=network. Look up destination IPs with GetIntelTool.",
        backstory="You analyse connections and DNS. You quote event ids.",
        tools=[events_tool, intel_tool],
        llm=llm,
        verbose=True,
    )
    endpoint_agent = Agent(
        role="Endpoint Analyst",
        goal="Describe process and file evidence using GetEventsTool with source=endpoint.",
        backstory="You analyse host process trees. You quote event ids.",
        tools=[events_tool],
        llm=llm,
        verbose=True,
    )
    identity_agent = Agent(
        role="Identity Analyst",
        goal="Describe authentication evidence using GetEventsTool with source=identity.",
        backstory="You analyse logins and locations. You quote event ids.",
        tools=[events_tool],
        llm=llm,
        verbose=True,
    )
    reconcile_agent = Agent(
        role="Evidence Reconciler",
        goal="Compare the three specialist outputs, name conflicts, and give a most-likely story with uncertainty.",
        backstory="You do not invent new logs. You only reason over quoted event ids.",
        llm=llm,
        verbose=True,
    )
    report_agent = Agent(
        role="Incident Report Writer",
        goal="Write What happened, Supporting evidence (ids), Conflicts, Likely explanation, Recommended human response.",
        backstory="You write for a human analyst. You never claim you blocked a host.",
        llm=llm,
        verbose=True,
    )

    ticket_task = Task(
        description=(
            "Load incident {incident_id} with GetTicketTool. Summarise the question the analyst asked. "
            "Do not investigate logs yourself."
        ),
        expected_output="Short ticket brief with time window.",
        agent=coordinator,
    )
    network_task = Task(
        description=(
            "For incident {incident_id}, call GetEventsTool with source=network. "
            "For each destination IP or domain, call GetIntelTool. Quote every event id you use."
        ),
        expected_output="Network hypothesis with event ids and intel results.",
        agent=network_agent,
        context=[ticket_task],
    )
    endpoint_task = Task(
        description=(
            "For incident {incident_id}, call GetEventsTool with source=endpoint. "
            "Describe parent-child processes and files. Quote event ids. Do not invent processes."
        ),
        expected_output="Endpoint hypothesis with event ids.",
        agent=endpoint_agent,
        context=[ticket_task],
    )
    identity_task = Task(
        description=(
            "For incident {incident_id}, call GetEventsTool with source=identity. "
            "Note locations, MFA, failures. Quote event ids."
        ),
        expected_output="Identity hypothesis with event ids.",
        agent=identity_agent,
        context=[ticket_task],
    )
    reconcile_task = Task(
        description=(
            "Compare network, endpoint, and identity findings for {incident_id}. "
            "If they disagree, say so explicitly. Most-likely explanation must stay within cited events. "
            "If identity is normal but host/network are not, do not claim credential theft."
        ),
        expected_output="Conflict list, timeline of cited ids, likely explanation, uncertainty.",
        agent=reconcile_agent,
        context=[ticket_task, network_task, endpoint_task, identity_task],
    )
    report_task = Task(
        description=(
            "Write the final CyberRecon assessment for {incident_id} with headings: "
            "What happened; Supporting evidence; Where evidence conflicts; "
            "Most likely explanation; Recommended response. Include event ids."
        ),
        expected_output="Markdown incident report grounded in event ids.",
        agent=report_agent,
        context=[reconcile_task, network_task, endpoint_task, identity_task],
    )

    return Crew(
        agents=[
            coordinator,
            network_agent,
            endpoint_agent,
            identity_agent,
            reconcile_agent,
            report_agent,
        ],
        tasks=[
            ticket_task,
            network_task,
            endpoint_task,
            identity_task,
            reconcile_task,
            report_task,
        ],
        process=Process.sequential,
        verbose=True,
    )


def _task_text(task: Task) -> str:
    output = getattr(task, "output", None)
    if output is None:
        return ""
    raw = getattr(output, "raw", None)
    return raw if isinstance(raw, str) and raw.strip() else str(output)


def save_run(incident_id: str, tasks: list[Task], final_text: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = RUNS_DIR / incident_id / stamp
    folder.mkdir(parents=True, exist_ok=True)
    for filename, task in zip(TASK_FILES, tasks, strict=True):
        (folder / filename).write_text(_task_text(task), encoding="utf-8")
    (folder / "report.md").write_text(final_text, encoding="utf-8")
    return folder


def investigate(incident_id: str) -> tuple[str, Path]:
    from cyberrecon.ingest import run as ingest

    ingest()
    crew = build_crew()
    result = crew.kickoff(inputs={"incident_id": incident_id})
    text = str(result)
    folder = save_run(incident_id, list(crew.tasks), text)
    assert_grounded(incident_id, text)
    return text, folder


if __name__ == "__main__":
    import sys

    incident_id = sys.argv[1] if len(sys.argv) > 1 else "case-b"
    text, folder = investigate(incident_id)
    print(text)
    print(f"\nSaved run: {folder}")
