from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from adk_app.agent_session_runner import _persist_evaluation_artifact
from adk_app.callbacks import LifecycleMonitoringPlugin


def _run_folder(root: Path) -> Path:
    folder = root / "runs" / "adk" / "case-b" / "20261115-220000"
    folder.mkdir(parents=True)
    (folder / "state.json").write_text(
        json.dumps(
            {
                "incident_id": "case-b",
                "network_findings": "### ATT&CK candidate mappings\n[]",
                "endpoint_findings": "### ATT&CK candidate mappings\n[]",
                "incident_report": "Observed ep-11.",
            }
        ),
        encoding="utf-8",
    )
    (folder / "incident_report.md").write_text("Observed ep-11.", encoding="utf-8")
    return folder


def test_normal_investigation_persistence_writes_linked_evaluation_artifact(monkeypatch) -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        folder = _run_folder(root)
        monkeypatch.setattr("cyberrecon.evaluation.assert_grounded", lambda *_args: None)
        monkeypatch.setattr("cyberrecon.evaluation.parse_attack_mappings", lambda *_args: [])
        monkeypatch.setattr("adk_app.agent_session_runner.ROOT", root)

        output = _persist_evaluation_artifact(
            incident_id="case-b",
            run_folder=folder,
            monitor=LifecycleMonitoringPlugin(),
            started=time.perf_counter(),
            span_records=[],
            status="completed",
        )

        report = json.loads(output.read_text(encoding="utf-8"))
        assert output.name == "case-b-20261115-220000.json"
        assert report["incident_id"] == "case-b"
        assert report["run_id"] == "20261115-220000"
        assert report["status"] == "completed"
        assert report["timing"]["total_duration_ms"] is not None


def test_failed_investigation_persistence_keeps_partial_metrics(monkeypatch) -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        folder = _run_folder(root)
        (folder / "state.json").write_text(json.dumps({"incident_id": "case-b"}), encoding="utf-8")
        (folder / "incident_report.md").write_text("", encoding="utf-8")
        monkeypatch.setattr("cyberrecon.evaluation.assert_grounded", lambda *_args: None)
        monkeypatch.setattr("cyberrecon.evaluation.parse_attack_mappings", lambda *_args: [])
        monkeypatch.setattr("adk_app.agent_session_runner.ROOT", root)

        output = _persist_evaluation_artifact(
            incident_id="case-b",
            run_folder=folder,
            monitor=LifecycleMonitoringPlugin(),
            started=time.perf_counter(),
            span_records=[],
            status="failed",
        )

        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["status"] == "failed"
        assert report["run_id"] == folder.name
        assert report["timing"]["total_duration_ms"] is not None
        assert report["grounding"] == {"checked": False, "passed": None, "reason": None}
