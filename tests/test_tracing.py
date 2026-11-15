from __future__ import annotations

import logging

import pytest

from cyberrecon.tracing import extract_context, inject_context, traced_span


def test_trace_spans_log_safe_metadata_and_duration(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="cyberrecon.tracing"):
        with traced_span("test.adk", component="adk", operation="unit"):
            pass

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "trace_span" in output
    assert "name=test.adk" in output
    assert "component=adk" in output
    assert "duration_ms=" in output
    assert "api-key" not in output


def test_a2a_context_propagates_trace_id_without_payload_data(caplog) -> None:
    carrier: dict[str, str] = {}
    with caplog.at_level(logging.INFO, logger="cyberrecon.tracing"):
        with traced_span("test.client", component="a2a-client", operation="request"):
            inject_context(carrier)
            with traced_span(
                "test.server",
                component="a2a-server",
                operation="request",
                parent_context=extract_context(carrier),
            ):
                pass

    lines = [record.getMessage() for record in caplog.records if "trace_span" in record.getMessage()]
    assert len(lines) == 2
    trace_ids = {line.split("trace_id=", 1)[1].split()[0] for line in lines}
    assert len(trace_ids) == 1
    assert "case-b" not in "\n".join(lines)


def test_trace_span_marks_error_without_recording_exception_text(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="cyberrecon.tracing"):
        with pytest.raises(RuntimeError, match="sensitive incident text"):
            with traced_span("test.failure", component="mcp-server", operation="tool"):
                raise RuntimeError("sensitive incident text")

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "status=StatusCode.ERROR" in output
    assert "error_type=RuntimeError" in output
    assert "sensitive incident text" not in output
