from agentshield.dashboard import build_dashboard_data


def test_multicloud_dashboard_aggregation():
    reports = [
        {
            "_source": "aws.json",
            "summary": {"score": 90, "risk_level": "LOW", "findings": 1, "severity": {"HIGH": 1}},
            "metadata": {"provider": "aws", "role_assessments": [{"name": "AgentRole", "blast_radius": "HIGH", "risk_points": 50, "candidate_ai_role": True, "attached_policies": ["PolicyA"]}]},
            "findings": [{"rule_id": "A", "title": "AWS risk", "severity": "HIGH", "file": "aws://x"}],
        },
        {
            "_source": "gcp.json",
            "summary": {"score": 70, "risk_level": "MEDIUM", "findings": 1, "severity": {"MEDIUM": 1}},
            "metadata": {"provider": "gcp", "identity_assessments": [{"name": "agent@p", "member_type": "serviceAccount", "blast_radius": "MEDIUM", "risk_points": 20, "candidate_ai_identity": True, "roles": ["roles/aiplatform.user"]}]},
            "findings": [{"rule_id": "G", "title": "GCP risk", "severity": "MEDIUM", "file": "gcp://x"}],
        },
    ]
    data = build_dashboard_data(reports)
    assert data["overall_score"] == 80
    assert data["overall_risk"] == "MEDIUM"
    assert len(data["providers"]) == 2
    assert data["identities"][0]["name"] == "AgentRole"
    assert len(data["findings"]) == 2
