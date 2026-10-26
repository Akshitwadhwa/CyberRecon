"""ADK sequential investigation. Findings move through session state, not CrewAI context."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import dotenv_values, load_dotenv
from google.adk.agents import LlmAgent
from google.adk.agents.sequential_agent import SequentialAgent
from google.adk.models.lite_llm import LiteLlm

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

load_dotenv(ROOT.parent / ".env")
PROJECT_ENV = ROOT / ".env"


def _load_project_environment(project_root: Path = ROOT) -> dict[str, str | None]:
    """Load the project environment after any parent/process defaults."""
    project_env = project_root / ".env"
    load_dotenv(project_env, override=True)
    return {key: value for key, value in dotenv_values(project_env).items()}


PROJECT_ENV_VALUES = _load_project_environment()

from cyberrecon.queries import events_text, intel_text, ticket_text  # noqa: E402


def _model() -> LiteLlm:
    name = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
    if "/" not in name:
        name = f"openai/{name}"
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("Add OPENAI_API_KEY to the project .env before starting ADK")
    key_source = str(PROJECT_ENV) if PROJECT_ENV_VALUES.get("OPENAI_API_KEY") else "process environment"
    print(
        "ADK LLM configuration: "
        f"key_source={key_source} key_prefix={api_key[:7]} "
        f"key_length={len(api_key)} model={name}"
    )
    return LiteLlm(model=name)


def get_ticket(incident_id: str) -> str:
    """Return the analyst ticket for an incident id such as case-b."""
    return ticket_text(incident_id)


def get_events(incident_id: str, source: str) -> str:
    """Return evidence rows for one incident. source is network, endpoint, or identity."""
    return events_text(incident_id, source)


def get_intel(indicator: str) -> str:
    """Look up one IP address or domain in the local intel snapshot."""
    return intel_text(indicator)


MODEL = _model()

coordinator = LlmAgent(
    name="InvestigationCoordinator",
    model=MODEL,
    description="Reads the incident ticket and states the question.",
    instruction="""You are the investigation coordinator.
The incident id is {incident_id}.
Call get_ticket with that exact incident id.
Summarise the analyst question and the time window.
Do not investigate logs and do not invent events.
""",
    tools=[get_ticket],
    output_key="ticket_brief",
)

network_agent = LlmAgent(
    name="NetworkAnalyst",
    model=MODEL,
    description="Reads network evidence and intel.",
    instruction="""You are the network analyst.
Incident id: {incident_id}
Ticket:
{ticket_brief}

Call get_events with that incident id and source network.
For every destination IP or domain in those rows, call get_intel.
Quote every event id you use. Use only tool results.
Do not decide whether the account was stolen. Report connections and intel only.
""",
    tools=[get_events, get_intel],
    output_key="network_findings",
)

endpoint_agent = LlmAgent(
    name="EndpointAnalyst",
    model=MODEL,
    description="Reads process and file evidence.",
    instruction="""You are the endpoint analyst. You cannot see other analysts' chat.
Incident id: {incident_id}
Ticket:
{ticket_brief}

Call get_events with that incident id and source endpoint before you answer.
Describe only process and file rows from that tool. Quote those event ids.
Do not discuss network connections or login locations.
""",
    tools=[get_events],
    include_contents="none",
    output_key="endpoint_findings",
)

identity_agent = LlmAgent(
    name="IdentityAnalyst",
    model=MODEL,
    description="Reads login evidence.",
    instruction="""You are the identity analyst. You cannot see other analysts' chat.
Incident id: {incident_id}
Ticket:
{ticket_brief}

Call get_events with that incident id and source identity before you answer.
Describe only login rows from that tool. Quote those event ids.
Do not discuss processes or outbound connections.
""",
    tools=[get_events],
    include_contents="none",
    output_key="identity_findings",
)

reconciler = LlmAgent(
    name="EvidenceReconciler",
    model=MODEL,
    description="Compares the three specialist findings stored in session state.",
    include_contents="none",
    instruction="""You reconcile an investigation. Do not call tools and do not invent events.
Use only the findings already stored in session state.

Network findings:
{network_findings}

Endpoint findings:
{endpoint_findings}

Identity findings:
{identity_findings}

If the specialists disagree, say so. If identity looks normal but the host or network does not, do not claim credential theft.
Name the conflict, list cited event ids, give the likely story, and state what is still uncertain.
""",
    output_key="reconciliation",
)

report_writer = LlmAgent(
    name="IncidentReportWriter",
    model=MODEL,
    description="Writes the final assessment from session state.",
    include_contents="none",
    instruction="""Write the final assessment from session state only. Do not invent event ids.
Do not claim a host was blocked.
Do not infer credential exploitation, account takeover, data exfiltration, or a named malware family unless the cited evidence explicitly establishes it.
When identity shows a normal MFA login from the usual office while endpoint or network activity is suspicious, describe suspicious behavior during an already-authenticated session and state the remaining uncertainty.

Reconciliation:
{reconciliation}

Network findings:
{network_findings}

Endpoint findings:
{endpoint_findings}

Identity findings:
{identity_findings}

Use these headings:
What happened
Supporting evidence
Where evidence conflicts
Most likely explanation
Recommended response
""",
    output_key="incident_report",
)

root_agent = SequentialAgent(
    name="CyberReconPipeline",
    description="Ticket, then network, endpoint, and identity, then reconcile and report. Each step reads session state.",
    sub_agents=[
        coordinator,
        network_agent,
        endpoint_agent,
        identity_agent,
        reconciler,
        report_writer,
    ],
)
