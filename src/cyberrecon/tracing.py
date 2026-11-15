"""Local OpenTelemetry tracing with safe, metadata-only export."""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import contextmanager
from typing import Iterator

from opentelemetry import propagate, trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, set_span_in_context

LOGGER = logging.getLogger("cyberrecon.tracing")
TRACE_ENV = "CYBERRECON_TRACE_ID"
SPAN_RECORDS: list[dict[str, object]] = []


def get_or_create_trace_id() -> str:
    value = os.getenv(TRACE_ENV, "").strip().lower()
    try:
        if len(value) == 32 and int(value, 16) != 0:
            return value
    except ValueError:
        pass
    value = uuid.uuid4().hex
    os.environ[TRACE_ENV] = value
    return value


def _shared_parent_context():
    parent = SpanContext(
        trace_id=int(get_or_create_trace_id(), 16),
        span_id=int(uuid.uuid4().hex[:16], 16),
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return set_span_in_context(NonRecordingSpan(parent))


class _SafeSpanExporter:
    """Export only controlled span metadata to the local logger."""

    def export(self, spans):
        for span in spans:
            context = span.get_span_context()
            status = getattr(span.status, "status_code", span.status)
            duration_ms = round((span.end_time - span.start_time) / 1_000_000, 3)
            error_type = span.attributes.get("error.type", "")
            SPAN_RECORDS.append(
                {
                    "trace_id": f"{context.trace_id:032x}",
                    "span_id": f"{context.span_id:016x}",
                    "name": span.name,
                    "component": span.attributes.get("cyberrecon.component", "unknown"),
                    "operation": span.attributes.get("cyberrecon.operation", "unknown"),
                    "duration_ms": duration_ms,
                    "status": str(status),
                    "error_type": error_type or None,
                }
            )
            LOGGER.info(
                "trace_span trace_id=%032x span_id=%016x name=%s component=%s duration_ms=%s status=%s error_type=%s",
                context.trace_id,
                context.span_id,
                span.name,
                span.attributes.get("cyberrecon.component", "unknown"),
                duration_ms,
                status,
                error_type,
            )
        return 0

    def shutdown(self):
        return None


def configure_tracing() -> None:
    """Install the local safe exporter when no SDK provider is configured."""
    get_or_create_trace_id()
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = trace.get_tracer_provider()
        if provider.__class__.__name__ == "ProxyTracerProvider":
            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(_SafeSpanExporter()))
            trace.set_tracer_provider(provider)
    except ImportError:
        return None


def extract_context(carrier: dict[str, str]):
    return propagate.extract(carrier)


def inject_context(carrier: dict[str, str]) -> None:
    propagate.inject(carrier)


def start_span(name: str, *, component: str, operation: str, parent_context=None):
    configure_tracing()
    span = trace.get_tracer("cyberrecon").start_span(
        name, context=parent_context or _shared_parent_context()
    )
    span.set_attribute("cyberrecon.component", component)
    span.set_attribute("cyberrecon.operation", operation)
    return span


@contextmanager
def traced_span(
    name: str,
    *,
    component: str,
    operation: str,
    parent_context=None,
) -> Iterator:
    configure_tracing()
    with trace.get_tracer("cyberrecon").start_as_current_span(
        name, context=parent_context or _shared_parent_context()
    ) as span:
        span.set_attribute("cyberrecon.component", component)
        span.set_attribute("cyberrecon.operation", operation)
        try:
            yield span
        except Exception as exc:
            span.set_attribute("error.type", type(exc).__name__)
            span.set_status(trace.Status(trace.StatusCode.ERROR))
            raise


def current_trace_id() -> str:
    context = trace.get_current_span().get_span_context()
    return f"{context.trace_id:032x}" if context.is_valid else get_or_create_trace_id()


def get_span_records() -> list[dict[str, object]]:
    return [dict(record) for record in SPAN_RECORDS]
