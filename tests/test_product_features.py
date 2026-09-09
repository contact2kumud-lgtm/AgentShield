from agentshield.baseline import compare_payloads
from agentshield.graph import build_mermaid
from agentshield.models import Finding, ScanResult, Severity


def test_baseline_diff_new_and_resolved_findings():
    old = {
        "summary": {"score": 80},
        "findings": [
            {"rule_id": "OLD", "file": "a", "title": "Old issue", "severity": "MEDIUM"},
            {"rule_id": "KEEP", "file": "b", "title": "Persistent", "severity": "LOW"},
        ],
    }
    new = {
        "summary": {"score": 70},
        "findings": [
            {"rule_id": "NEW", "file": "c", "title": "New issue", "severity": "HIGH"},
            {"rule_id": "KEEP", "file": "b", "title": "Persistent", "severity": "LOW"},
        ],
    }
    diff = compare_payloads(old, new)
    assert diff["score_delta"] == -10
    assert len(diff["new_findings"]) == 1
    assert len(diff["resolved_findings"]) == 1
    assert len(diff["persistent_findings"]) == 1


def test_mermaid_graph_for_gcp():
    result = ScanResult(
        root="gcp://projects",
        findings=[Finding("X", "Risk", Severity.HIGH, "m", "gcp://x")],
        files_scanned=1,
        metadata={
            "provider": "gcp",
            "identity_assessments": [{
                "name": "agent@p.iam.gserviceaccount.com", "blast_radius": "HIGH",
                "roles": ["roles/aiplatform.admin"], "projects": ["p"],
            }],
        },
    )
    graph = build_mermaid(result)
    assert "Google Cloud" in graph
    assert "aiplatform.admin" in graph
    assert "agent@p.iam.gserviceaccount.com" in graph
