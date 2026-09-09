# GCP read-only setup

AgentShield uses Application Default Credentials (ADC) and read-only REST calls.

For a local workstation:

```bash
gcloud auth application-default login
```

You can grant equivalent read-only permissions with a custom role based on `agentshield-reader-role.yaml`, or combine Google Cloud predefined read-only roles such as:

- Browser (`roles/browser`) for project discovery and project IAM policy visibility
- IAM Viewer (`roles/iam.viewer`) for IAM roles, service accounts, and service-account key metadata
- Logs Viewer (`roles/logging.viewer`) for logging sink visibility

Grant only at the scope AgentShield needs to assess. For production, prefer a dedicated security-audit identity rather than an everyday administrator account.

AgentShield never creates, updates, deletes, disables, or rotates GCP resources.
