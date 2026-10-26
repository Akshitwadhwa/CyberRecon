"""Small, dependency-light A2A JSON-RPC contract for the CrewAI service."""

from __future__ import annotations

import re
import uuid
from typing import Any

from cyberrecon.schemas import InvestigationFindings

CARD_PATHS = ("/.well-known/agent-card.json", "/.well-known/agent.json")
RPC_PATH = "/a2a"
_INCIDENT_RE = re.compile(r"\bincident\s+([A-Za-z0-9_-]+)\b", re.IGNORECASE)


def agent_card(base_url: str) -> dict[str, Any]:
    return {
        "name": "CyberRecon CrewAI Investigator",
        "description": "Runs the existing CrewAI cybersecurity investigation and returns validated findings.",
        "url": f"{base_url.rstrip('/')}{RPC_PATH}",
        "version": "0.3.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "investigate-incident",
                "name": "Investigate incident",
                "description": "Run the existing CrewAI investigation for one incident id.",
                "tags": ["cybersecurity", "incident-response"],
                "examples": ["Investigate incident case-b"],
            }
        ],
    }


def extract_incident_id(params: dict[str, Any]) -> str:
    metadata = params.get("metadata") or {}
    candidate = metadata.get("incident_id")
    if candidate is None:
        message = params.get("message") or {}
        for part in message.get("parts") or []:
            text = part.get("text") if isinstance(part, dict) else None
            match = _INCIDENT_RE.search(text or "")
            if match:
                candidate = match.group(1)
                break
    if not isinstance(candidate, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", candidate):
        raise ValueError("Request must identify one incident using metadata.incident_id or message text")
    return candidate


def success_response(request_id: Any, findings: InvestigationFindings) -> dict[str, Any]:
    task_id = str(uuid.uuid4())
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "id": task_id,
            "status": {"state": "completed"},
            "artifacts": [
                {
                    "artifactId": str(uuid.uuid4()),
                    "name": "investigation-findings",
                    "parts": [{"type": "data", "data": findings.model_dump(mode="json")}],
                }
            ],
        },
    }


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
