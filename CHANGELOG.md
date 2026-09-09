# Changelog

## 1.3.0

- Added Google Cloud IAM and AI workload identity scanner.
- Added GCP project IAM blast-radius analysis for Owner, Editor, IAM administration, service-account impersonation, secret access, KMS decryption, storage administration, and Vertex AI roles.
- Added detection of public IAM members (`allUsers` / `allAuthenticatedUsers`).
- Added user-managed service-account key detection with higher severity for likely AI/agent identities.
- Added custom GCP role analysis for IAM privilege escalation and sensitive-data permissions.
- Added Cloud Audit Logs data-access visibility and project log-sink checks.
- Added multi-cloud baseline snapshots and drift comparison (`--baseline-out`, `--compare-with`).
- Added CI drift gate (`--fail-on-new`) and minimum posture score gate (`--min-score`).
- Added Mermaid blast-radius / attack-path graph export (`--graph`).
- Added GCP support to HTML reports and CLI identity ranking.
- Added unified multi-cloud executive dashboard aggregation for AWS, Azure, GCP and repository reports.
- Expanded automated test suite to AWS, Azure, GCP, baseline drift and graph generation.

## 1.2.0

- Added Microsoft Azure + Entra ID live security connector.
- Added Azure RBAC blast-radius analysis and AI workload identity heuristics.
- Added Azure Policy, Defender for Cloud, Activity Log export and supported AI resource posture checks.
- Added Microsoft Graph principal enrichment.

## 1.1.0

- Added live AWS IAM and cloud security connector.
- Added IAM role blast-radius scoring and AI-role heuristics.
- Added AWS account posture checks for CloudTrail, GuardDuty, Config, S3 public access block, EBS encryption, Security Hub and root MFA.

## 1.0.0

- Initial repository scanner with secrets, dangerous execution, agent controls, dependencies, GitHub Actions, HTML/JSON/SARIF output and CI severity gates.
