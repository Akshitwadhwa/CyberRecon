"""Structured performance and grounding evaluation for existing investigations."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adk_app.callbacks import LifecycleMonitoringPlugin
from cyberrecon.guardrails import assert_grounded, parse_attack_mappings
from cyberrecon.tracing import get_span_records


def _sum_usage(records: list[dict[str, Any]]) -> dict[str, int] | None:
    if not records:
        return None
    totals: dict[str, int] = {}
    for record in records:
        for key, value in record.items():
            if key == "agent":
                continue
            if isinstance(value, (int, float)):
                totals[key] = totals.get(key, 0) + int(value)
    return totals or None


def build_evaluation_report(
    *,
    incident_id: str,
    run_folder: Path,
    total_duration_ms: float,
    monitor: LifecycleMonitoringPlugin,
) -> dict[str, Any]:
    state_path = run_folder / "state.json"
    report_path = run_folder / "incident_report.md"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    report_text = report_path.read_text(encoding="utf-8")

    grounding = {"checked": True, "passed": False, "reason": None}
    try:
        assert_grounded(incident_id, report_text)
        grounding["passed"] = True
    except ValueError as exc:
        grounding["reason"] = str(exc)

    mappings: dict[str, Any] = {}
    for key in ("network_findings", "endpoint_findings"):
        try:
            values = parse_attack_mappings(incident_id, str(state.get(key) or ""))
            mappings[key] = {
                "valid": True,
                "count": len(values),
                "statuses": [item.status for item in values],
                "technique_ids": [item.technique_id for item in values],
            }
        except ValueError as exc:
            mappings[key] = {"valid": False, "reason": str(exc)}

    spans = get_span_records()
    a2a_spans = [item for item in spans if item["name"] == "a2a.client.request"]
    mcp_tools: dict[str, list[float]] = {}
    for item in monitor.metrics["tool_durations_ms"]:
        if isinstance(item, dict) and "tool" in item:
            mcp_tools.setdefault(str(item["tool"]), []).append(item["duration_ms"])
    rag_durations = [
        item["duration_ms"]
        for item in monitor.metrics["tool_durations_ms"]
        if isinstance(item, dict) and item.get("tool") == "search_attack_knowledge"
    ]

    usage = _sum_usage(monitor.metrics["llm_usage"])
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "run_folder": str(run_folder),
        "timing": {
            "total_duration_ms": round(total_duration_ms, 3),
            "agent_durations_ms": monitor.metrics["agent_durations_ms"],
            "mcp_tool_durations_ms": mcp_tools,
            "a2a_duration_ms": a2a_spans[0]["duration_ms"] if a2a_spans else None,
            "rag_retrieval_durations_ms": rag_durations,
        },
        "llm": {
            "token_usage": usage,
            "estimated_cost_usd": None,
            "cost_status": "unavailable_without_provider_pricing_metadata",
        },
        "grounding": grounding,
        "attack_mappings": mappings,
        "errors": monitor.metrics["errors"],
        "trace": {
            "trace_id": spans[0]["trace_id"] if spans else None,
            "span_count": len(spans),
        },
    }


async def evaluate_case(incident_id: str = "case-b", output_root: Path | None = None) -> Path:
    from adk_app.agent_session_runner import run_investigation

    monitor = LifecycleMonitoringPlugin()
    started = time.perf_counter()
    run_folder = await run_investigation(
        incident_id,
        monitor=monitor,
        validate_outputs=False,
    )
    report = build_evaluation_report(
        incident_id=incident_id,
        run_folder=run_folder,
        total_duration_ms=(time.perf_counter() - started) * 1000,
        monitor=monitor,
    )
    destination_root = output_root or Path("runs") / "evaluations"
    destination_root.mkdir(parents=True, exist_ok=True)
    output = destination_root / f"{incident_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output
