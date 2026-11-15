from __future__ import annotations

import json
import tempfile
from pathlib import Path

from adk_app.callbacks import LifecycleMonitoringPlugin
from cyberrecon.evaluation import build_evaluation_report


def test_evaluation_report_preserves_unavailable_cost_and_metrics() -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        run_folder = Path(directory)
        state = {
            "network_findings": "### ATT&CK candidate mappings\n- T1059.001 | PowerShell | ep-11 | candidate | Hidden execution.",
            "endpoint_findings": "### ATT&CK candidate mappings\n[]",
        }
        (run_folder / "state.json").write_text(json.dumps(state), encoding="utf-8")
        (run_folder / "incident_report.md").write_text("Observed ep-11.", encoding="utf-8")
        monitor = LifecycleMonitoringPlugin()
        monitor.metrics["agent_durations_ms"].append({"agent": "NetworkAnalyst", "duration_ms": 12.5})
        monitor.metrics["tool_durations_ms"].append({"tool": "search_attack_knowledge", "duration_ms": 4.2, "status": "success"})
        monitor.metrics["llm_usage"].append({"agent": "NetworkAnalyst", "total_tokens": 100})

        report = build_evaluation_report(
            incident_id="case-b",
            run_folder=run_folder,
            total_duration_ms=25.0,
            monitor=monitor,
        )

    assert report["timing"]["total_duration_ms"] == 25.0
    assert report["timing"]["rag_retrieval_durations_ms"] == [4.2]
    assert report["llm"]["token_usage"] == {"total_tokens": 100}
    assert report["llm"]["estimated_cost_usd"] is None
    assert report["grounding"]["passed"] is True
    assert report["attack_mappings"]["network_findings"]["valid"] is True
