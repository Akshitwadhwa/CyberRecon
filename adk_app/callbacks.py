"""Safe lifecycle logging for the ADK investigation runner."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from google.adk.plugins import BasePlugin
from opentelemetry.trace import Status, StatusCode
from cyberrecon.tracing import current_trace_id, start_span
from cyberrecon.safe_errors import exception_metadata


LOGGER = logging.getLogger("cyberrecon.adk.lifecycle")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _duration_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


class LifecycleMonitoringPlugin(BasePlugin):
    """Log ADK lifecycle metadata without logging prompts, arguments, or results."""

    def __init__(self, logger: logging.Logger = LOGGER) -> None:
        super().__init__(name="cyberrecon_lifecycle_monitor")
        self._logger = logger
        self._agent_starts: dict[int, float] = {}
        self._agent_spans: dict[int, Any] = {}
        self._tool_starts: defaultdict[str, list[float]] = defaultdict(list)
        self._tool_spans: defaultdict[str, list[Any]] = defaultdict(list)
        self._run_span: Any = None
        self.metrics = {
            "agent_durations_ms": [],
            "tool_durations_ms": [],
            "llm_usage": [],
            "errors": [],
        }

    def _log(self, level: int, event: str, **fields: Any) -> None:
        safe_fields = " ".join(f"{key}={value}" for key, value in fields.items())
        self._logger.log(
            level,
            "adk_event=%s timestamp=%s trace_id=%s %s",
            event,
            _timestamp(),
            current_trace_id(),
            safe_fields,
        )

    async def before_run_callback(self, *, invocation_context):
        self._run_span = start_span("adk.investigation", component="adk", operation="investigation")
        return None

    async def after_run_callback(self, *, invocation_context):
        if self._run_span:
            self._run_span.end()
            self._run_span = None

    async def on_run_error_callback(self, *, invocation_context, error):
        if self._run_span:
            self._run_span.set_attribute("error.type", type(error).__name__)
            self._run_span.set_status(Status(StatusCode.ERROR))
            self._run_span.end()
            self._run_span = None
        self.metrics["errors"].append({"component": "run", "name": "investigation", "error_type": type(error).__name__})
        self._log(logging.ERROR, "run_error", status="error", error_type=type(error).__name__, **exception_metadata(error))

    async def before_agent_callback(self, *, agent, callback_context):
        self._agent_starts[id(agent)] = time.perf_counter()
        self._agent_spans[id(agent)] = start_span("adk.agent", component="adk", operation=agent.name)
        self._log(logging.INFO, "agent_started", agent=agent.name)
        return None

    async def after_agent_callback(self, *, agent, callback_context):
        started = self._agent_starts.pop(id(agent), time.perf_counter())
        if handle := self._agent_spans.pop(id(agent), None):
            handle.end()
        self.metrics["agent_durations_ms"].append(
            {"agent": agent.name, "duration_ms": _duration_ms(started)}
        )
        self._log(
            logging.INFO,
            "agent_completed",
            agent=agent.name,
            duration_ms=_duration_ms(started),
            status="success",
        )
        return None

    async def on_agent_error_callback(self, *, agent, callback_context, error):
        started = self._agent_starts.pop(id(agent), time.perf_counter())
        if handle := self._agent_spans.pop(id(agent), None):
            handle.set_attribute("error.type", type(error).__name__)
            handle.set_status(Status(StatusCode.ERROR))
            handle.end()
        self.metrics["errors"].append({"component": "agent", "name": agent.name, "error_type": type(error).__name__})
        self._log(logging.ERROR, "agent_error", agent=agent.name, duration_ms=_duration_ms(started), status="error", error_type=type(error).__name__, **exception_metadata(error))

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        self._tool_starts[tool.name].append(time.perf_counter())
        self._tool_spans[tool.name].append(start_span("adk.tool", component="adk", operation=tool.name))
        self._log(logging.INFO, "tool_started", tool=tool.name)
        return None

    def _finish_tool(
        self,
        tool,
        *,
        status: str,
        level: int,
        error_type: str | None = None,
        error_fields: dict[str, Any] | None = None,
    ) -> None:
        starts = self._tool_starts[tool.name]
        started = starts.pop() if starts else time.perf_counter()
        if self._tool_spans[tool.name]:
            span = self._tool_spans[tool.name].pop()
            if not self._tool_spans[tool.name]:
                self._tool_spans.pop(tool.name, None)
            if error_type:
                span.set_attribute("error.type", error_type)
                span.set_status(Status(StatusCode.ERROR))
            span.end()
        if not starts:
            self._tool_starts.pop(tool.name, None)
        self.metrics["tool_durations_ms"].append(
            {"tool": tool.name, "duration_ms": _duration_ms(started), "status": status}
        )
        fields: dict[str, Any] = {
            "tool": tool.name,
            "duration_ms": _duration_ms(started),
            "status": status,
        }
        if error_type:
            fields["error_type"] = error_type
        if error_fields:
            fields.update(error_fields)
        self._log(level, "tool_completed" if status == "success" else "tool_error", **fields)

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        self._finish_tool(tool, status="success", level=logging.INFO)
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        self._finish_tool(
            tool,
            status="error",
            level=logging.ERROR,
            error_type=type(error).__name__,
            error_fields=exception_metadata(error),
        )
        self.metrics["errors"].append({"component": "tool", "name": tool.name, "error_type": type(error).__name__, **exception_metadata(error)})
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        usage = getattr(llm_response, "usage_metadata", None)
        if usage is None:
            return None
        fields = {}
        for name in (
            "prompt_token_count",
            "candidates_token_count",
            "total_token_count",
            "input_tokens",
            "output_tokens",
            "total_tokens",
        ):
            value = getattr(usage, name, None)
            if isinstance(value, (int, float)):
                fields[name] = value
        if fields:
            fields["agent"] = getattr(callback_context, "agent_name", "unknown")
            self.metrics["llm_usage"].append(fields)
        return None

