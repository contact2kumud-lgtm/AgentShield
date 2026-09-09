# Azure read-only setup

AgentShield can authenticate with `DefaultAzureCredential` or Azure CLI credentials.

For a simple local test:

```bash
az login
az account set --subscription <subscription-id>
pip install ".[azure]"
agentshield azure --credential cli --subscription <subscription-id>
```

The included `agentshield-reader-role.json` is a starting point for a custom read-only Azure role. Replace the placeholder subscription under `AssignableScopes` before creating it.

Microsoft Graph principal-name enrichment is separate from Azure RBAC. If the signed-in identity cannot resolve directory objects, AgentShield still analyzes assignments using principal IDs and records a **visibility gap** instead of silently assuming the identity is safe.

For production automation, prefer a dedicated service principal/workload identity with only the read permissions required for the subscriptions being assessed.
