"""Minimal A2A JSON-RPC client used by the ADK runner."""

from __future__ import annotations

import json
import os
import urllib.request
import uuid
from typing import Any

from cyberrecon.a2a_contract import RPC_PATH
from cyberrecon.schemas import InvestigationFindings
from cyberrecon.tracing import inject_context, traced_span


class A2AClientError(RuntimeError):
    pass


DEFAULT_A2A_TIMEOUT_SECONDS = 600.0
A2A_TIMEOUT_ENV = "CREWAI_A2A_TIMEOUT_SECONDS"
A2A_TOKEN_ENV = "CYBERRECON_A2A_TOKEN"


def _auth_headers() -> dict[str, str]:
    token = os.getenv(A2A_TOKEN_ENV, "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


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
    with traced_span("a2a.client.request", component="a2a-client", operation="message/send"):
        card_url = f"{base_url.rstrip('/')}/.well-known/agent-card.json"
        card_request = urllib.request.Request(card_url, headers=_auth_headers(), method="GET")
        with urllib.request.urlopen(card_request, timeout=timeout) as response:
            card = json.load(response)
        endpoint = card.get("url") or f"{base_url.rstrip('/')}{RPC_PATH}"
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {"metadata": {"incident_id": incident_id}, "message": {"role": "user", "parts": [{"type": "text", "text": f"Investigate incident {incident_id}"}]}},
        }
        headers = {"Content-Type": "application/json", **_auth_headers()}
        inject_context(headers)
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.load(response)
        if "error" in body:
            raise A2AClientError("A2A request failed")
        try:
            data = body["result"]["artifacts"][0]["parts"][0]["data"]
            return InvestigationFindings.model_validate(data)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise A2AClientError("A2A response did not contain valid investigation findings") from exc
