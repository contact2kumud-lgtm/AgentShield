# AgentShield

Open-source AI &amp; multi-cloud security posture platform for AWS, Azure and GCP.
=======

**Open-source AI-agent and multi-cloud security posture scanner for AWS, Azure, GCP and source repositories.**

AgentShield treats an AI agent as a privileged workload identity. It connects code-level risks with cloud identity, permissions, secrets, logging, governance and blast radius.

It is designed to answer five questions:

1. What can the agent or workload identity access?
2. What actions can it perform?
3. Can it escalate privileges, impersonate another identity, or delegate access?
4. Are sensitive actions observable and governed?
5. What is the likely blast radius if the agent, prompt, token, toolchain or workload identity is compromised?

---

## Why AgentShield?

Traditional SAST tools focus on vulnerable code. CSPM tools focus on cloud configuration. IAM tools focus on identities. AgentShield focuses on the security boundary **between AI-agent code, workload identity, cloud authorization and AI platform exposure**.

### Current capabilities

- AI-agent source/configuration scanning
- Secrets and dangerous execution checks
- CI/CD and software supply-chain checks
- Live AWS IAM role, policy and trust analysis
- Live Azure RBAC + Microsoft Entra identity analysis
- Live GCP IAM + service-account analysis
- AI workload identity heuristics across all three clouds
- Cloud identity blast-radius scoring
- Long-lived service-account key detection on GCP
- Azure AI / Azure ML posture checks
- AWS cloud security control checks
- Cloud logging / governance visibility checks
- ISO 27001 / OWASP LLM / CWE metadata
- JSON, HTML and SARIF reporting
- Mermaid blast-radius / attack-path graphs
- Baseline snapshots and security drift comparison
- Unified multi-cloud executive dashboard from AWS/Azure/GCP reports
- CI gates on severity, minimum score, and newly introduced findings

---

## Install

Repository scanner only:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install .
```

AWS connector:

```bash
pip install ".[aws]"
```

Azure connector:

```bash
pip install ".[azure]"
```

GCP connector:

```bash
pip install ".[gcp]"
```

All cloud connectors:

```bash
pip install ".[cloud]"
```

Development:

```bash
pip install ".[cloud,dev]"
```

---

# 1. Scan an AI-agent repository

```bash
agentshield scan /path/to/agent
```

The shorthand still works:

```bash
agentshield .
```

Generate security artifacts:

```bash
agentshield scan . \
  --json scan-results.json \
  --html agentshield-report.html \
  --sarif agentshield.sarif \
  --graph blast-radius.mmd \
  --fail-on high \
  --min-score 80
```

### Repository checks

- committed API keys, AWS keys and private keys
- administrator / owner roles
- wildcard permissions
- shell and dynamic code execution
- human-in-the-loop controls disabled
- audit logging disabled
- unrestricted network binding
- unpinned dependencies
- risky GitHub Actions permissions
- `pull_request_target` workflow risk

---

# 2. Scan AWS

AgentShield uses the standard boto3 credential chain and performs read-only API calls.

```bash
agentshield aws --profile security-audit --region ap-south-1
```

Generate reports:

```bash
agentshield aws \
  --profile security-audit \
  --region ap-south-1 \
  --html aws-agentshield-report.html \
  --json aws-agentshield.json \
  --graph aws-blast-radius.mmd
```

Scan only likely AI workload roles:

```bash
agentshield aws --profile security-audit --ai-only
```

Scope by role naming convention:

```bash
agentshield aws --profile security-audit --role-pattern "*Agent*"
```

### AWS IAM blast-radius checks

- `AdministratorAccess`
- `PowerUserAccess` / `IAMFullAccess`
- `Action: "*"`
- service wildcards such as `s3:*`
- `Allow` + `NotAction`
- unrestricted `iam:PassRole`
- `sts:AssumeRole`
- common IAM privilege-escalation actions
- broad Secrets Manager / SSM / KMS / S3 data access
- wildcard destructive permissions
- trust policies allowing any principal
- cross-account trust and ExternalId presence

### AWS account posture checks

- Root MFA
- CloudTrail logging and multi-region coverage
- GuardDuty
- AWS Config
- account-level S3 Block Public Access
- EBS encryption by default
- Security Hub

Read-only policy example:

```text
examples/aws/agentshield-readonly-policy.json
```

---

# 3. Scan Microsoft Azure + Entra ID

AgentShield supports `DefaultAzureCredential` and Azure CLI credentials.

```bash
az login
agentshield azure --credential cli
```

Restrict to one subscription:

```bash
agentshield azure \
  --credential cli \
  --subscription 00000000-0000-0000-0000-000000000000
```

Generate reports:

```bash
agentshield azure \
  --credential cli \
  --html azure-agentshield-report.html \
  --json azure-agentshield.json \
  --sarif azure-agentshield.sarif \
  --graph azure-blast-radius.mmd
```

Only likely AI/agent identities:

```bash
agentshield azure --credential cli --ai-only
```

Target a naming convention:

```bash
agentshield azure --credential cli --principal-pattern "*Copilot*"
```

### Azure RBAC blast-radius checks

- Owner
- Contributor
- User Access Administrator
- Role Based Access Control Administrator
- wildcard control-plane/data-plane permissions
- custom-role privilege escalation
- role assignment / role definition write access
- managed identity delegation
- Key Vault secret/key access
- storage account key access
- Cognitive Services / AI key access
- broad subscription or management-group scope
- AI/agent identity + privileged-role combinations

### Azure governance and AI checks

- Azure Policy assignments
- Microsoft Defender for Cloud pricing coverage
- subscription Activity Log diagnostic export
- Azure OpenAI / Cognitive Services public network access
- local/key authentication (`disableLocalAuth`)
- Azure Machine Learning public network exposure
- Microsoft Graph principal enrichment

Azure setup examples:

```text
examples/azure/
```

---

# 4. Scan Google Cloud

AgentShield uses Google Application Default Credentials (ADC) and read-only REST API calls.

For local development:

```bash
gcloud auth application-default login
```

Run across accessible projects:

```bash
agentshield gcp
```

Restrict to specific projects:

```bash
agentshield gcp \
  --project my-ai-prod \
  --project my-data-prod
```

Only likely AI/agent identities:

```bash
agentshield gcp --ai-only
```

Generate reports and graph:

```bash
agentshield gcp \
  --html gcp-agentshield-report.html \
  --json gcp-agentshield.json \
  --sarif gcp-agentshield.sarif \
  --graph gcp-blast-radius.mmd
```

### GCP IAM blast-radius checks

- `roles/owner`
- `roles/editor`
- Project IAM Admin / IAM Security Admin
- Service Account Token Creator
- Service Account Key Admin
- Service Account User / impersonation risk
- Secret Manager sensitive access
- KMS decryption access
- broad Cloud Storage administration
- Vertex AI administrative roles
- public IAM members: `allUsers` and `allAuthenticatedUsers`
- custom roles with IAM privilege-escalation permissions
- custom roles with secret/decrypt/sensitive data access
- likely AI service account + high-privilege role combinations

### GCP service-account and logging checks

- user-managed service-account keys
- elevated severity for AI/agent identities with long-lived keys
- Data Access audit configuration visibility
- Cloud Logging project export sink visibility

GCP read-only setup examples:

```text
examples/gcp/
```

---

# 5. Baselines and security drift

Create a baseline after an approved assessment:

```bash
agentshield gcp --baseline-out approved-gcp.baseline.json
```

Later, compare the current environment:

```bash
agentshield gcp --compare-with approved-gcp.baseline.json
```

Example:

```text
Baseline diff | score 88 -> 61 (-27)
New findings: 2 | Resolved: 1 | Persistent: 3
  + [CRITICAL] AS-GCP-IAM-004 IAM privilege-escalation capable role @ gcp://...
  + [HIGH] AS-GCP-SA-001 User-managed service-account key detected @ gcp://...
  - [MEDIUM] AS-GCP-LOG-002 No project log export sink detected @ gcp://...
```

Fail CI only when new findings appear:

```bash
agentshield scan . \
  --compare-with approved.baseline.json \
  --fail-on-new
```

This is useful for **security drift detection** instead of repeatedly failing on accepted legacy findings.

---

# 6. Security score gates

Require a minimum posture score:

```bash
agentshield aws --min-score 80
```

Combine with severity gating:

```bash
agentshield azure \
  --min-score 85 \
  --fail-on high
```

---

# 7. Blast-radius / attack-path graph

Generate a Mermaid graph:

```bash
agentshield gcp --graph blast-radius.mmd
```

The graph models relationships such as:

```text
AI workload identity
        |
        +--> privileged cloud role
        |         |
        |         +--> project / subscription / account
        |
        +--> sensitive data access
        |
        +--> workload trust / impersonation path
```

The `.mmd` file can be rendered by GitHub, Mermaid Live, VS Code extensions, or documentation pipelines.

---

# 8. Unified multi-cloud dashboard

Aggregate existing AgentShield JSON reports into one executive dashboard:

```bash
agentshield dashboard \
  aws-agentshield.json \
  azure-agentshield.json \
  gcp-agentshield.json \
  --html multicloud-dashboard.html \
  --json multicloud-dashboard.json
```

The dashboard provides:

- one cross-cloud posture score
- per-provider AWS / Azure / GCP score and risk
- critical/high finding counts
- highest blast-radius identities across clouds
- AI workload identity indicators
- top security findings in one view

This makes AgentShield useful both for engineers doing individual scans and security leaders reviewing multi-cloud posture.

---

# Example CLI output

### AWS

```text
AgentShield | score 22/100 | risk CRITICAL | roles 18 | findings 7
AWS account 123456789012 | region ap-south-1 | principal arn:aws:sts::123456789012:assumed-role/SecurityAudit/agentshield
[ROLE CRITICAL] AI CustomerSupportAgentRole | risk-points 100 | findings 4
[ROLE LOW     ] -- ReportingReadOnlyRole | risk-points 0 | findings 0
```

### Azure

```text
AgentShield | score 0/100 | risk CRITICAL | assignments 34 | findings 9
Azure tenants 11111111-1111-1111-1111-111111111111 | subscriptions 2 | AI resources 3
[IDENTITY CRITICAL] AI CustomerSupport-AI-Agent | servicePrincipal | risk-points 100 | findings 5
[IDENTITY LOW     ] -- Security Reader | user | risk-points 0 | findings 0
```

### GCP

```text
AgentShield | score 7/100 | risk CRITICAL | IAM memberships 27 | findings 8
GCP projects 3 | service accounts 18
[IDENTITY CRITICAL] AI customer-agent@ai-prod.iam.gserviceaccount.com | serviceAccount | risk-points 100 | findings 4
[IDENTITY LOW     ] -- security-reader@example.com | user | risk-points 0 | findings 0
```

---

# HTML report

The standalone HTML report includes:

- overall security score
- cloud/provider context
- IAM role / identity blast-radius ranking
- AI identity heuristic indicator
- risk points and reasons
- findings with remediation
- assessment visibility gaps

Sanitized examples are under `docs/`.

---

# GitHub integration

The included workflow under `.github/workflows/agentshield.yml` scans pushes and pull requests, generates SARIF, and can upload findings to GitHub Code Scanning.

```bash
agentshield scan . \
  --sarif agentshield.sarif \
  --fail-on high \
  --min-score 80
```

For mature repositories, baseline drift gating can reduce noise:

```bash
agentshield scan . \
  --compare-with .security/agentshield.baseline.json \
  --fail-on-new
```

---

# Architecture

```text
                               +-----------------------+
                               |      AgentShield      |
                               +-----------+-----------+
                                           |
          +----------------+---------------+----------------+----------------+
          |                |                                |                |
          v                v                                v                v
   Repository Scanner   AWS Connector                 Azure Connector   GCP Connector
  +------------------+ +----------------+            +----------------+ +----------------+
  | Source / Config  | | IAM Roles      |            | Entra IDs      | | Project IAM    |
  | Secrets          | | Trust Policies |            | Azure RBAC     | | Service Accts   |
  | Agent Controls   | | Policies       |            | Custom Roles   | | SA Keys         |
  | Dependencies     | | Priv Esc       |            | AI Resources   | | Custom Roles    |
  | GitHub Actions   | | Cloud Posture  |            | Gov / Logging  | | Logging         |
  +--------+---------+ +--------+-------+            +--------+-------+ +--------+-------+
           |                    |                             |                  |
           +--------------------+-----------------------------+------------------+
                                                |
                                                v
                                      +--------------------+
                                      | Finding + Risk     |
                                      | Blast Radius       |
                                      | Drift Comparison   |
                                      +---------+----------+
                                                |
                           +--------------------+---------------------+
                           v                    v                     v
                          CLI            HTML / JSON / SARIF      Mermaid Graph
```

---

# Security philosophy

An AI agent with a weak prompt boundary but no privileges has limited impact. An AI agent with broad cloud permissions can become an infrastructure-level security incident.

AgentShield therefore prioritizes:

- least privilege
- bounded trust
- identity isolation
- short-lived credentials
- human control for high-impact actions
- auditable actions
- sensitive-data boundaries
- blast-radius reduction
- continuous drift detection

---

# Roadmap

- unified one-command live multi-cloud assessment
- interactive web dashboard with historical trends
- visual graph explorer
- MCP server permission analysis
- AWS Bedrock Agent configuration adapter
- deeper Azure AI Foundry checks
- Vertex AI resource configuration checks
- OpenAI / Anthropic agent configuration adapters
- policy-as-code rule packs
- signed assessment reports
- cloud identity drift history
- remediation pull-request generation

---

# Important limitations

AgentShield is a security review accelerator, not proof of exploitability or a complete effective-permission simulator.

For AWS, effective access can also be constrained or expanded by permissions boundaries, session policies, resource policies, SCPs and service-specific authorization behavior.

For Azure, effective access can be affected by deny assignments, management-group inheritance, RBAC conditions, PIM activation, group membership, resource-specific authorization and data-plane controls.

For GCP, effective access can also be affected by organization/folder inheritance, deny policies, IAM Conditions, Principal Access Boundary policies, resource-specific IAM, service agents and organization policies.

Treat blast-radius findings as prioritized review signals and validate high-impact findings against native cloud authorization/security tooling before remediation.

---

## Contributing

Issues and pull requests are welcome. New security checks should include a threat scenario, severity, remediation guidance and automated tests.

## License

Apache License 2.0
>>>>>>> 4630a54 (Initial release: AgentShield v1.3 Multi-Cloud Security Platform)
