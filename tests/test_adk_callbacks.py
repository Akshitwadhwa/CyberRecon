from __future__ import annotations

import asyncio
import logging
import time
from types import SimpleNamespace

from adk_app.callbacks import LifecycleMonitoringPlugin


def _run(coro):
    return asyncio.run(coro)


def test_agent_lifecycle_logs_name_status_and_duration_without_content(caplog) -> None:
    plugin = LifecycleMonitoringPlugin()
    agent = SimpleNamespace(name="NetworkAnalyst")
    context = SimpleNamespace()

    with caplog.at_level(logging.INFO, logger="cyberrecon.adk.lifecycle"):
        _run(plugin.before_agent_callback(agent=agent, callback_context=context))
        _run(plugin.after_agent_callback(agent=agent, callback_context=context))

    messages = [record.getMessage() for record in caplog.records]
    assert "adk_event=agent_started" in messages[0]
    assert "agent=NetworkAnalyst" in messages[0]
    assert "adk_event=agent_completed" in messages[1]
    assert "status=success" in messages[1]
    assert "duration_ms=" in messages[1]
    assert all("case-b" not in message for message in messages)


def test_tool_lifecycle_logs_only_safe_metadata(caplog) -> None:
    plugin = LifecycleMonitoringPlugin()
    tool = SimpleNamespace(name="get_incident_events")
    context = SimpleNamespace()
    sensitive_args = {"incident_id": "case-b", "api_key": "do-not-log"}

    with caplog.at_level(logging.INFO, logger="cyberrecon.adk.lifecycle"):
        _run(plugin.before_tool_callback(tool=tool, tool_args=sensitive_args, tool_context=context))
        _run(plugin.after_tool_callback(tool=tool, tool_args=sensitive_args, tool_context=context, result={"events": []}))

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "tool=get_incident_events" in output
    assert "duration_ms=" in output
    assert "case-b" not in output
    assert "do-not-log" not in output


def test_agent_and_tool_errors_log_type_without_error_text(caplog) -> None:
    plugin = LifecycleMonitoringPlugin()
    agent = SimpleNamespace(name="EndpointAnalyst")
    tool = SimpleNamespace(name="lookup_threat_intel")
    context = SimpleNamespace()
    error = RuntimeError("secret incident payload")

    with caplog.at_level(logging.ERROR, logger="cyberrecon.adk.lifecycle"):
        _run(plugin.before_agent_callback(agent=agent, callback_context=context))
        _run(plugin.on_agent_error_callback(agent=agent, callback_context=context, error=error))
        _run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=context))
        _run(plugin.on_tool_error_callback(tool=tool, tool_args={}, tool_context=context, error=error))
        _run(plugin.on_run_error_callback(invocation_context=context, error=error))

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "adk_event=agent_error" in output
    assert "adk_event=tool_error" in output
    assert "adk_event=run_error" in output
    assert "error_type=RuntimeError" in output
    assert "secret incident payload" not in output


def test_transport_error_logging_is_redacted_and_typed(monkeypatch, caplog) -> None:
    plugin = LifecycleMonitoringPlugin()
    agent = SimpleNamespace(name="InvestigationCoordinator")
    context = SimpleNamespace()

    class ProviderError(RuntimeError):
        status_code = 503
        code = "temporarily_unavailable"
        request_id = "req_callback_test"

    error = ProviderError("secret prompt and authorization header")
    error.__cause__ = ConnectionError("private incident data")
    # Keep this contract test independent of OpenTelemetry provider startup.
    monkeypatch.setattr("adk_app.callbacks.current_trace_id", lambda: "trace-test")
    plugin._agent_starts[id(agent)] = time.perf_counter()
    with caplog.at_level(logging.ERROR, logger="cyberrecon.adk.lifecycle"):
        _run(plugin.on_agent_error_callback(agent=agent, callback_context=context, error=error))
    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "exception_types=ProviderError>ConnectionError" in output
    assert "http_status=503" in output
    assert "provider_error_code=temporarily_unavailable" in output
    assert "request_id=req_callback_test" in output
    assert "secret prompt" not in output
    assert "authorization header" not in output
