from agentshield.scanners.azure import AzureSecurityScanner


class FakeAzureAdapter:
    def list_subscriptions(self):
        return [{"id": "sub-1", "name": "Production", "state": "Enabled", "tenant_id": "tenant-1"}]

    def list_role_definitions(self, subscription_id):
        return [
            {
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/owner-id",
                "name": "Owner", "role_type": "BuiltInRole",
                "permissions": [{"actions": ["*"], "not_actions": [], "data_actions": [], "not_data_actions": []}],
            },
            {
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/reader-id",
                "name": "Reader", "role_type": "BuiltInRole",
                "permissions": [{"actions": ["*/read"], "not_actions": [], "data_actions": [], "not_data_actions": []}],
            },
        ]

    def list_role_assignments(self, subscription_id):
        return [
            {
                "id": "ra-1", "principal_id": "sp-ai", "principal_type": "ServicePrincipal",
                "role_definition_id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/owner-id",
                "scope": f"/subscriptions/{subscription_id}", "condition": "",
            },
            {
                "id": "ra-2", "principal_id": "user-safe", "principal_type": "User",
                "role_definition_id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/reader-id",
                "scope": f"/subscriptions/{subscription_id}/resourceGroups/rg-safe", "condition": "",
            },
        ]

    def resolve_principals(self, principal_ids):
        return {
            "sp-ai": {"id": "sp-ai", "name": "CustomerSupport-AI-Agent", "type": "servicePrincipal"},
            "user-safe": {"id": "user-safe", "name": "Security Reader", "type": "user"},
        }

    def list_policy_assignments(self, subscription_id):
        return [{"name": "security-baseline"}]

    def list_defender_pricings(self, subscription_id):
        return [{"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}]

    def list_diagnostic_settings(self, subscription_id):
        return [{"name": "activity-to-law"}]

    def list_ai_resources(self, subscription_id):
        return [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/openai-prod",
                "name": "openai-prod", "type": "Microsoft.CognitiveServices/accounts", "location": "eastus",
                "properties": {"publicNetworkAccess": "Enabled", "disableLocalAuth": False},
            }
        ]


def test_azure_scanner_detects_ai_owner_blast_radius():
    result = AzureSecurityScanner(adapter=FakeAzureAdapter()).scan()
    ids = {f.rule_id for f in result.findings}
    assert "AS-AZ-RBAC-001" in ids
    assert "AS-AZ-RBAC-002" in ids
    assert "AS-AZ-RBAC-004" in ids
    assert "AS-AZ-AI-001" in ids
    assert "AS-AZ-AI-010" in ids
    assert "AS-AZ-AI-011" in ids
    identities = result.metadata["identity_assessments"]
    risky = next(x for x in identities if x["principal_id"] == "sp-ai")
    safe = next(x for x in identities if x["principal_id"] == "user-safe")
    assert risky["candidate_ai_identity"] is True
    assert risky["blast_radius"] == "CRITICAL"
    assert safe["blast_radius"] == "LOW"


def test_azure_ai_only_filter():
    result = AzureSecurityScanner(adapter=FakeAzureAdapter(), ai_only=True).scan()
    identities = result.metadata["identity_assessments"]
    assert len(identities) == 1
    assert identities[0]["name"] == "CustomerSupport-AI-Agent"
    assert result.files_scanned == 1
