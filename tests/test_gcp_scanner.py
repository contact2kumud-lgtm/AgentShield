from agentshield.scanners.gcp import GcpSecurityScanner


class FakeGcpAdapter:
    def list_projects(self):
        return [{"project_id": "ai-prod", "project_number": "123", "display_name": "AI Production", "state": "ACTIVE"}]

    def get_iam_policy(self, project_id):
        return {
            "version": 3,
            "bindings": [
                {"role": "roles/owner", "members": ["serviceAccount:customer-agent@ai-prod.iam.gserviceaccount.com"]},
                {"role": "roles/viewer", "members": ["user:reader@example.com"]},
                {"role": "roles/secretmanager.secretAccessor", "members": ["serviceAccount:customer-agent@ai-prod.iam.gserviceaccount.com"]},
            ],
            "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}],
        }

    def list_service_accounts(self, project_id):
        return [
            {"email": "customer-agent@ai-prod.iam.gserviceaccount.com", "displayName": "Customer AI Agent"},
            {"email": "safe@ai-prod.iam.gserviceaccount.com", "displayName": "Safe Worker"},
        ]

    def list_service_account_keys(self, project_id, email):
        if email.startswith("customer-agent"):
            return [{"name": "projects/ai-prod/serviceAccounts/x/keys/key1", "keyType": "USER_MANAGED", "validAfterTime": "2025-01-01T00:00:00Z"}]
        return []

    def get_role(self, role_name):
        return {}

    def list_log_sinks(self, project_id):
        return [{"name": "central-siem", "destination": "pubsub.googleapis.com/projects/sec/topics/logs"}]


def test_gcp_scanner_finds_risky_ai_service_account():
    result = GcpSecurityScanner(adapter=FakeGcpAdapter()).scan()
    ids = {f.rule_id for f in result.findings}
    assert "AS-GCP-IAM-002" in ids
    assert "AS-GCP-DATA-001" in ids
    assert "AS-GCP-AI-001" in ids
    assert "AS-GCP-SA-001" in ids
    identities = result.metadata["identity_assessments"]
    agent = next(i for i in identities if "customer-agent" in i["name"])
    reader = next(i for i in identities if i["name"] == "reader@example.com")
    assert agent["candidate_ai_identity"] is True
    assert agent["blast_radius"] == "CRITICAL"
    assert reader["blast_radius"] == "LOW"


def test_gcp_ai_only_filter():
    result = GcpSecurityScanner(adapter=FakeGcpAdapter(), ai_only=True).scan()
    identities = result.metadata["identity_assessments"]
    assert len(identities) == 1
    assert "customer-agent" in identities[0]["name"]
