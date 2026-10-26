"""Minimal A2A JSON-RPC client used by the ADK runner."""

from __future__ import annotations

import json
import os
import urllib.request
import uuid
from typing import Any

from cyberrecon.a2a_contract import RPC_PATH
from cyberrecon.schemas import InvestigationFindings


class A2AClientError(RuntimeError):
    pass


DEFAULT_A2A_TIMEOUT_SECONDS = 600.0
A2A_TIMEOUT_ENV = "CREWAI_A2A_TIMEOUT_SECONDS"


def get_a2a_timeout(timeout: float | None = None) -> float:
    """Return the configured HTTP timeout without changing request semantics."""
    value = timeout
    if value is None:
        raw_value = os.getenv(A2A_TIMEOUT_ENV, str(DEFAULT_A2A_TIMEOUT_SECONDS))
        try:
            value = float(raw_value)
        except ValueError as exc:
            raise A2AClientError(f"{A2A_TIMEOUT_ENV} must be a positive number") from exc
    if value <= 0:
        raise A2AClientError(f"{A2A_TIMEOUT_ENV} must be a positive number")
    return value


def invoke_crewai(
    base_url: str, incident_id: str, timeout: float | None = None
) -> InvestigationFindings:
    timeout = get_a2a_timeout(timeout)
    card_url = f"{base_url.rstrip('/')}/.well-known/agent-card.json"
    with urllib.request.urlopen(card_url, timeout=timeout) as response:
        card = json.load(response)
    endpoint = card.get("url") or f"{base_url.rstrip('/')}{RPC_PATH}"
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {"metadata": {"incident_id": incident_id}, "message": {"role": "user", "parts": [{"type": "text", "text": f"Investigate incident {incident_id}"}]}},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.load(response)
    if "error" in body:
        raise A2AClientError(body["error"].get("message", "A2A request failed"))
    try:
        data = body["result"]["artifacts"][0]["parts"][0]["data"]
        return InvestigationFindings.model_validate(data)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise A2AClientError("A2A response did not contain valid investigation findings") from exc
