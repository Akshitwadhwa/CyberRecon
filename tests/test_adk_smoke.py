from __future__ import annotations


def test_adk_root_pipeline_is_constructed() -> None:
    from adk_app.agent import root_agent

    assert root_agent.name == "CyberReconPipeline"
    assert [agent.name for agent in root_agent.sub_agents] == [
        "InvestigationCoordinator",
        "NetworkAnalyst",
        "EndpointAnalyst",
        "IdentityAnalyst",
        "EvidenceReconciler",
        "IncidentReportWriter",
    ]

    report_instruction = root_agent.sub_agents[-1].instruction
    assert "Do not infer credential exploitation" in report_instruction
    assert "data exfiltration" in report_instruction
    assert "already-authenticated session" in report_instruction
