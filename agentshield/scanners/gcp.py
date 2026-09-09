from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import Finding, ScanResult, Severity


AI_KEYWORDS = (
    "agent", "vertex", "gemini", "genai", "llm", "model", "assistant",
    "copilot", "chatbot", "bot", "rag", "ai-", "-ai", "ml-", "-ml",
)

CRITICAL_ROLES = {
    "roles/owner": (65, "Owner grants project-wide administrative control"),
    "roles/resourcemanager.projectIamAdmin": (55, "Can change project IAM policy"),
    "roles/iam.securityAdmin": (55, "Can administer IAM security policy"),
    "roles/iam.serviceAccountAdmin": (45, "Can administer service accounts"),
    "roles/iam.serviceAccountKeyAdmin": (50, "Can create/manage service-account keys"),
    "roles/iam.serviceAccountTokenCreator": (55, "Can mint credentials for service accounts"),
}

HIGH_ROLES = {
    "roles/editor": (38, "Editor has broad mutation capability"),
    "roles/iam.serviceAccountUser": (32, "Can act as service accounts on resources"),
    "roles/secretmanager.admin": (35, "Can administer secrets"),
    "roles/secretmanager.secretAccessor": (30, "Can read secret payloads"),
    "roles/storage.admin": (32, "Broad Cloud Storage administration"),
    "roles/storage.objectAdmin": (28, "Can read/write/delete storage objects"),
    "roles/cloudkms.admin": (35, "Can administer KMS resources"),
    "roles/cloudkms.cryptoKeyDecrypter": (30, "Can decrypt protected data"),
    "roles/aiplatform.admin": (38, "Can administer Vertex AI resources"),
}

AI_ROLES = {
    "roles/aiplatform.admin",
    "roles/aiplatform.user",
    "roles/aiplatform.serviceAgent",
    "roles/ml.admin",
    "roles/ml.developer",
}

PRIV_ESC_PERMISSION_PATTERNS = (
    "resourcemanager.projects.setIamPolicy",
    "iam.serviceAccounts.setIamPolicy",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.roles.update",
    "iam.roles.create",
)

SENSITIVE_PERMISSION_PATTERNS = (
    "secretmanager.versions.access",
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "storage.objects.get",
    "bigquery.tables.getData",
)

MUTATING_TOKENS = ("create", "update", "delete", "set", "patch", "write", "upload", "publish", "invoke")


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _role_short(role: str) -> str:
    return role.rsplit("/", 1)[-1]


def _member_type(member: str) -> str:
    if ":" not in member:
        return member
    return member.split(":", 1)[0]


def _candidate_ai_identity(name: str, roles: list[str]) -> bool:
    low = name.lower()
    return any(k in low for k in AI_KEYWORDS) or any(r in AI_ROLES or r.startswith("roles/aiplatform.") for r in roles)


@dataclass
class GcpIdentityAssessment:
    member: str
    name: str
    member_type: str
    candidate_ai_identity: bool
    risk_points: int = 0
    finding_count: int = 0
    reasons: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)
    blast_radius: str = "LOW"

    def add_risk(self, points: int, reason: str) -> None:
        self.risk_points += points
        if reason not in self.reasons:
            self.reasons.append(reason)

    def finalize(self) -> None:
        if self.risk_points >= 70:
            self.blast_radius = "CRITICAL"
        elif self.risk_points >= 40:
            self.blast_radius = "HIGH"
        elif self.risk_points >= 15:
            self.blast_radius = "MEDIUM"
        else:
            self.blast_radius = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "member": self.member,
            "name": self.name,
            "member_type": self.member_type,
            "candidate_ai_identity": self.candidate_ai_identity,
            "risk_points": min(self.risk_points, 100),
            "finding_count": self.finding_count,
            "reasons": self.reasons,
            "roles": sorted(set(self.roles)),
            "projects": sorted(set(self.projects)),
            "blast_radius": self.blast_radius,
        }


class GcpLiveAdapter:
    """Minimal read-only GCP adapter using Application Default Credentials and REST APIs."""

    CRM = "https://cloudresourcemanager.googleapis.com"
    IAM = "https://iam.googleapis.com"
    LOGGING = "https://logging.googleapis.com"

    def __init__(self, quota_project_id: str | None = None) -> None:
        try:
            import google.auth  # type: ignore
            from google.auth.transport.requests import AuthorizedSession  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                'GCP scanning requires google-auth. Install with: pip install "agentshield-security[gcp]"'
            ) from exc
        creds, default_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
            quota_project_id=quota_project_id,
        )
        self.default_project = default_project
        self.session = AuthorizedSession(creds)

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self.session.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json() if r.content else {}

    def _post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(url, json=body, timeout=30)
        r.raise_for_status()
        return r.json() if r.content else {}

    def list_projects(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        token = None
        while True:
            params: dict[str, Any] = {"pageSize": 100}
            if token:
                params["pageToken"] = token
            data = self._get(f"{self.CRM}/v3/projects:search", params)
            for p in data.get("projects", []):
                if p.get("state") == "DELETE_REQUESTED":
                    continue
                out.append({
                    "project_id": _norm(p.get("projectId")),
                    "project_number": _norm(p.get("name")).split("/")[-1],
                    "display_name": _norm(p.get("displayName")),
                    "state": _norm(p.get("state")),
                    "parent": _norm(p.get("parent")),
                })
            token = data.get("nextPageToken")
            if not token:
                break
        return out

    def get_iam_policy(self, project_id: str) -> dict[str, Any]:
        return self._post(
            f"{self.CRM}/v3/projects/{project_id}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
        )

    def list_service_accounts(self, project_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        token = None
        while True:
            params: dict[str, Any] = {"pageSize": 100}
            if token:
                params["pageToken"] = token
            data = self._get(f"{self.IAM}/v1/projects/{project_id}/serviceAccounts", params)
            out.extend(data.get("accounts", []))
            token = data.get("nextPageToken")
            if not token:
                break
        return out

    def list_service_account_keys(self, project_id: str, email: str) -> list[dict[str, Any]]:
        data = self._get(
            f"{self.IAM}/v1/projects/{project_id}/serviceAccounts/{email}/keys",
            {"keyTypes": "USER_MANAGED"},
        )
        return list(data.get("keys", []))

    def get_role(self, role_name: str) -> dict[str, Any]:
        # role_name may be roles/foo or projects/x/roles/foo
        return self._get(f"{self.IAM}/v1/{role_name}")

    def list_log_sinks(self, project_id: str) -> list[dict[str, Any]]:
        data = self._get(f"{self.LOGGING}/v2/projects/{project_id}/sinks")
        return list(data.get("sinks", []))


class GcpSecurityScanner:
    """Read-only GCP IAM, service-account and AI-workload blast-radius scanner."""

    def __init__(
        self,
        adapter: Any | None = None,
        projects: list[str] | None = None,
        principal_pattern: str | None = None,
        ai_only: bool = False,
        max_projects: int = 100,
        max_service_accounts: int = 500,
        quota_project_id: str | None = None,
    ) -> None:
        self.adapter = adapter or GcpLiveAdapter(quota_project_id=quota_project_id)
        self.requested_projects = set(projects or [])
        self.principal_pattern = principal_pattern
        self.ai_only = ai_only
        self.max_projects = max(1, max_projects)
        self.max_service_accounts = max(1, max_service_accounts)
        self.findings: list[Finding] = []
        self.visibility_gaps: list[str] = []

    def _gap(self, area: str, exc: Exception) -> None:
        text = f"{area}: {exc.__class__.__name__}: {str(exc)[:120]}"
        if text not in self.visibility_gaps:
            self.visibility_gaps.append(text)

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        message: str,
        location: str,
        evidence: str,
        remediation: str,
        category: str,
        iso27001: str | None = None,
    ) -> None:
        self.findings.append(Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            message=message,
            file=location,
            line=1,
            evidence=evidence[:500],
            remediation=remediation,
            category=category,
            cwe="CWE-250" if category in {"iam", "identity"} else None,
            owasp_llm="LLM06" if category in {"iam", "identity", "ai-resource"} else None,
            iso27001=iso27001,
        ))

    @staticmethod
    def _role_risk(role_name: str, role_details: dict[str, Any] | None = None) -> tuple[int, list[str], list[str]]:
        points = 0
        reasons: list[str] = []
        permissions: list[str] = []
        if role_name in CRITICAL_ROLES:
            p, reason = CRITICAL_ROLES[role_name]
            points += p; reasons.append(reason)
        elif role_name in HIGH_ROLES:
            p, reason = HIGH_ROLES[role_name]
            points += p; reasons.append(reason)
        if role_details:
            permissions = [_norm(x) for x in role_details.get("includedPermissions", [])]
            if any(fnmatch.fnmatch(p, pat) for p in permissions for pat in PRIV_ESC_PERMISSION_PATTERNS):
                points += 45; reasons.append("Custom role contains IAM privilege-escalation permissions")
            if any(fnmatch.fnmatch(p, pat) for p in permissions for pat in SENSITIVE_PERMISSION_PATTERNS):
                points += 25; reasons.append("Custom role can access secrets/decrypt/sensitive data")
            if any(any(t in p.lower() for t in MUTATING_TOKENS) for p in permissions):
                points += 12; reasons.append("Custom role contains mutating permissions")
        return min(points, 100), reasons, permissions

    def _assess_binding(
        self,
        project: dict[str, Any],
        role_name: str,
        members: list[str],
        assessments: dict[str, GcpIdentityAssessment],
        custom_role_cache: dict[str, dict[str, Any]],
    ) -> None:
        pid = project["project_id"]
        loc = f"gcp://projects/{pid}/iam/{_role_short(role_name)}"
        role_details: dict[str, Any] | None = None
        if role_name.startswith(f"projects/{pid}/roles/"):
            if role_name not in custom_role_cache:
                try:
                    custom_role_cache[role_name] = self.adapter.get_role(role_name)
                except Exception as exc:
                    self._gap(f"{pid} custom role {role_name}", exc)
                    custom_role_cache[role_name] = {}
            role_details = custom_role_cache.get(role_name) or None

        base_points, base_reasons, permissions = self._role_risk(role_name, role_details)

        for member in members:
            mtype = _member_type(member)
            display = member.split(":", 1)[1] if ":" in member else member
            if self.principal_pattern and not fnmatch.fnmatch(display.lower(), self.principal_pattern.lower()):
                continue
            candidate = _candidate_ai_identity(display, [role_name])
            if self.ai_only and not candidate:
                continue

            identity = assessments.get(member)
            if identity is None:
                identity = GcpIdentityAssessment(member, display, mtype, candidate)
                assessments[member] = identity
            identity.candidate_ai_identity = identity.candidate_ai_identity or candidate
            identity.roles.append(role_name)
            identity.projects.append(pid)
            before = len(self.findings)

            if member in {"allUsers", "allAuthenticatedUsers"}:
                sev = Severity.CRITICAL if role_name in CRITICAL_ROLES or base_points >= 45 else Severity.HIGH
                self._add(
                    "AS-GCP-IAM-001", "Public or internet-wide IAM binding", sev,
                    f"Project {pid} grants {role_name} to {member}.", loc,
                    f"member={member}; role={role_name}",
                    "Remove public IAM members unless the resource is intentionally public; use narrowly scoped identities instead.",
                    "iam", "A.5.15 Access control",
                )
                identity.add_risk(80 if sev == Severity.CRITICAL else 55, "Public IAM principal")

            if role_name == "roles/owner":
                self._add(
                    "AS-GCP-IAM-002", "Project Owner assignment", Severity.CRITICAL,
                    f"{display} has Owner on GCP project {pid}.", loc,
                    f"member={member}; role=roles/owner",
                    "Replace Owner with task-specific predefined/custom roles and use privileged access only when needed.",
                    "iam", "A.8.2 Privileged access rights",
                )
            elif role_name == "roles/editor":
                self._add(
                    "AS-GCP-IAM-003", "Broad Editor assignment", Severity.HIGH,
                    f"{display} has legacy Editor on GCP project {pid}.", loc,
                    f"member={member}; role=roles/editor",
                    "Replace primitive Editor with least-privilege predefined or custom roles.",
                    "iam", "A.8.2 Privileged access rights",
                )

            if role_name in {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin"}:
                self._add(
                    "AS-GCP-IAM-004", "IAM privilege-escalation capable role", Severity.CRITICAL,
                    f"{display} has {role_name}, enabling credential minting or IAM policy administration.", loc,
                    f"member={member}; role={role_name}",
                    "Restrict IAM administration and credential-minting roles to dedicated privileged identities with strong approval controls.",
                    "iam", "A.8.2 Privileged access rights",
                )

            if role_name in {"roles/secretmanager.secretAccessor", "roles/secretmanager.admin", "roles/cloudkms.cryptoKeyDecrypter"}:
                self._add(
                    "AS-GCP-DATA-001", "Sensitive secret/decryption access", Severity.HIGH,
                    f"{display} has sensitive data-access role {role_name} in project {pid}.", loc,
                    f"member={member}; role={role_name}",
                    "Scope secret/decryption access to exact workloads and resources; avoid project-wide grants for AI agents.",
                    "data", "A.8.3 Information access restriction",
                )

            if role_name.startswith("projects/") and permissions:
                if any(p in PRIV_ESC_PERMISSION_PATTERNS for p in permissions):
                    self._add(
                        "AS-GCP-IAM-005", "Custom role enables IAM privilege escalation", Severity.CRITICAL,
                        f"Custom role {role_name} contains permissions that can change IAM or mint credentials.", loc,
                        ", ".join([p for p in permissions if p in PRIV_ESC_PERMISSION_PATTERNS][:8]),
                        "Remove privilege-escalation permissions from workload roles and separate privileged administration duties.",
                        "iam", "A.8.2 Privileged access rights",
                    )
                if any(p in SENSITIVE_PERMISSION_PATTERNS for p in permissions):
                    self._add(
                        "AS-GCP-DATA-002", "Custom role can access sensitive data", Severity.HIGH,
                        f"Custom role {role_name} grants sensitive data read/decrypt capabilities.", loc,
                        ", ".join([p for p in permissions if p in SENSITIVE_PERMISSION_PATTERNS][:8]),
                        "Constrain custom-role permissions and bind them at the narrowest resource scope possible.",
                        "data", "A.8.3 Information access restriction",
                    )

            if candidate and base_points >= 30:
                self._add(
                    "AS-GCP-AI-001", "AI workload identity has excessive GCP blast radius", Severity.CRITICAL if base_points >= 50 else Severity.HIGH,
                    f"Likely AI/agent identity {display} holds broad role {role_name} in project {pid}.", loc,
                    f"member={member}; role={role_name}; risk_points={base_points}",
                    "Create a dedicated least-privilege service account for the AI workload; constrain projects, APIs, secrets and impersonation paths.",
                    "ai-resource", "A.8.2 Privileged access rights",
                )

            identity.add_risk(base_points, "; ".join(base_reasons) or f"Role {role_name}")
            identity.finding_count += len(self.findings) - before

    def _service_account_checks(self, project_id: str, assessments: dict[str, GcpIdentityAssessment]) -> int:
        try:
            accounts = self.adapter.list_service_accounts(project_id)[: self.max_service_accounts]
        except Exception as exc:
            self._gap(f"{project_id} service accounts", exc)
            return 0
        scanned = 0
        for sa in accounts:
            scanned += 1
            email = _norm(sa.get("email"))
            name = _norm(sa.get("displayName")) or email
            member = f"serviceAccount:{email}" if email else ""
            candidate = _candidate_ai_identity(f"{name} {email}", assessments.get(member).roles if member in assessments else [])
            if self.ai_only and not candidate:
                continue
            try:
                keys = self.adapter.list_service_account_keys(project_id, email)
            except Exception as exc:
                self._gap(f"{project_id} service-account keys {email}", exc)
                continue
            for key in keys:
                key_type = _norm(key.get("keyType"))
                if key_type and key_type != "USER_MANAGED":
                    continue
                valid_after = _norm(key.get("validAfterTime"))
                age_days = None
                if valid_after:
                    try:
                        dt = datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - dt).days
                    except ValueError:
                        pass
                sev = Severity.CRITICAL if candidate else Severity.HIGH
                msg = f"Service account {email} has a user-managed key"
                if age_days is not None:
                    msg += f" approximately {age_days} days old"
                msg += "."
                self._add(
                    "AS-GCP-SA-001", "User-managed service-account key detected", sev,
                    msg, f"gcp://projects/{project_id}/serviceAccounts/{email}/keys",
                    f"key={_norm(key.get('name'))}; validAfter={valid_after or 'unknown'}",
                    "Prefer Workload Identity Federation, metadata-based credentials or service-account impersonation; remove long-lived user-managed keys.",
                    "identity", "A.5.17 Authentication information",
                )
                identity = assessments.get(member)
                if identity:
                    identity.add_risk(45 if candidate else 30, "Long-lived user-managed service-account key")
                    identity.finding_count += 1
        return scanned

    def _project_controls(self, project_id: str, policy: dict[str, Any]) -> None:
        audit_configs = policy.get("auditConfigs", []) or []
        has_data_access = False
        for cfg in audit_configs:
            for ac in cfg.get("auditLogConfigs", []) or []:
                if ac.get("logType") in {"DATA_READ", "DATA_WRITE"}:
                    has_data_access = True
        if not has_data_access:
            self._add(
                "AS-GCP-LOG-001", "Cloud Audit Logs data-access logging not evident", Severity.MEDIUM,
                f"Project {project_id} IAM policy does not show DATA_READ/DATA_WRITE audit configuration.",
                f"gcp://projects/{project_id}/auditLogs", "auditConfigs lacks DATA_READ/DATA_WRITE",
                "Enable appropriate Data Access audit logs for sensitive services, balancing security visibility and log cost.",
                "monitoring", "A.8.15 Logging",
            )
        try:
            sinks = self.adapter.list_log_sinks(project_id)
            if not sinks:
                self._add(
                    "AS-GCP-LOG-002", "No project log export sink detected", Severity.MEDIUM,
                    f"No Cloud Logging project sink was returned for {project_id}.",
                    f"gcp://projects/{project_id}/logging", "sinks=0",
                    "For production/security-sensitive projects, export important logs to a protected centralized logging/SIEM destination.",
                    "monitoring", "A.8.15 Logging",
                )
        except Exception as exc:
            self._gap(f"{project_id} log sinks", exc)

    def scan(self) -> ScanResult:
        self.findings = []
        self.visibility_gaps = []
        try:
            projects = self.adapter.list_projects()
        except Exception as exc:
            raise RuntimeError(f"Unable to enumerate GCP projects with Application Default Credentials: {exc}") from exc
        if self.requested_projects:
            projects = [p for p in projects if p.get("project_id") in self.requested_projects]
        projects = projects[: self.max_projects]
        if not projects:
            wanted = ", ".join(sorted(self.requested_projects)) or "current credentials"
            raise RuntimeError(f"No accessible GCP projects found for {wanted}.")

        assessments: dict[str, GcpIdentityAssessment] = {}
        project_meta: list[dict[str, Any]] = []
        custom_role_cache: dict[str, dict[str, Any]] = {}
        bindings_scanned = 0
        service_accounts_scanned = 0

        for project in projects:
            pid = _norm(project.get("project_id"))
            if not pid:
                continue
            try:
                policy = self.adapter.get_iam_policy(pid)
            except Exception as exc:
                self._gap(f"{pid} IAM policy", exc)
                policy = {"bindings": []}
            included = 0
            for binding in policy.get("bindings", []) or []:
                role_name = _norm(binding.get("role"))
                members = [_norm(m) for m in binding.get("members", []) or [] if _norm(m)]
                if not role_name or not members:
                    continue
                self._assess_binding(project, role_name, members, assessments, custom_role_cache)
                included += len(members)
                bindings_scanned += len(members)
            service_count = self._service_account_checks(pid, assessments)
            service_accounts_scanned += service_count
            self._project_controls(pid, policy)
            project_meta.append({
                "project_id": pid,
                "display_name": _norm(project.get("display_name")),
                "state": _norm(project.get("state")),
                "iam_memberships_scanned": included,
                "service_accounts_scanned": service_count,
            })

        for ident in assessments.values():
            ident.candidate_ai_identity = ident.candidate_ai_identity or _candidate_ai_identity(ident.name, ident.roles)
            ident.finalize()

        if self.visibility_gaps:
            self._add(
                "AS-GCP-VIS-001", "GCP assessment visibility is incomplete", Severity.MEDIUM,
                "One or more read-only GCP APIs could not be queried, so the assessment may be incomplete.",
                "gcp://scanner/visibility", "; ".join(self.visibility_gaps[:8]),
                "Grant the scanner the documented read-only permissions and enabled APIs, then rerun the assessment.",
                "visibility", "A.5.36 Compliance with policies, rules and standards",
            )

        self.findings.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value], f.file, f.rule_id))
        ordered = sorted(assessments.values(), key=lambda x: (-min(x.risk_points, 100), x.name.lower()))
        return ScanResult(
            root="gcp://projects",
            findings=self.findings,
            files_scanned=bindings_scanned,
            metadata={
                "provider": "gcp",
                "projects": project_meta,
                "identity_assessments": [x.to_dict() for x in ordered],
                "service_accounts_scanned": service_accounts_scanned,
                "visibility_gaps": self.visibility_gaps,
            },
        )
