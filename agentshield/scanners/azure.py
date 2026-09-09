from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models import Finding, ScanResult, Severity


AI_IDENTITY_KEYWORDS = (
    "agent", "copilot", "openai", "genai", "llm", "chatbot", "bot-", "-bot",
    "azureml", "machinelearning", "cognitive", "assistant", "rag", "ai-", "-ai",
)
AI_RESOURCE_TYPES = {
    "microsoft.cognitiveservices/accounts",
    "microsoft.machinelearningservices/workspaces",
    "microsoft.botservice/botservices",
}
HIGH_PRIVILEGE_ROLES = {
    "owner": (100, "CRITICAL"),
    "user access administrator": (90, "CRITICAL"),
    "role based access control administrator": (95, "CRITICAL"),
    "contributor": (55, "HIGH"),
}
PRIV_ESC_ACTION_PATTERNS = (
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roledefinitions/write",
    "microsoft.authorization/elevateaccess/action",
    "microsoft.managedidentity/userassignedidentities/assign/action",
)
SENSITIVE_ACTION_PATTERNS = (
    "microsoft.keyvault/vaults/secrets/getsecret/action",
    "microsoft.keyvault/vaults/keys/decrypt/action",
    "microsoft.keyvault/vaults/keys/sign/action",
    "microsoft.storage/storageaccounts/listkeys/action",
    "microsoft.cognitiveservices/accounts/listkeys/action",
    "microsoft.cognitiveservices/accounts/regeneratekey/action",
    "microsoft.machinelearningservices/workspaces/listkeys/action",
)
MUTATING_TOKENS = ("/write", "/delete", "/action")


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _role_key(role_definition_id: str) -> str:
    value = role_definition_id.rstrip("/")
    return value.split("/")[-1].lower()


def _scope_level(scope: str) -> str:
    s = scope.rstrip("/").lower()
    if "/managementgroups/" in s and "/subscriptions/" not in s:
        return "MANAGEMENT_GROUP"
    if re.fullmatch(r"/subscriptions/[^/]+", s):
        return "SUBSCRIPTION"
    if "/resourcegroups/" in s and "/providers/" not in s:
        return "RESOURCE_GROUP"
    return "RESOURCE"


def _is_ai_scope(scope: str) -> bool:
    s = scope.lower()
    return any(x in s for x in (
        "microsoft.cognitiveservices", "microsoft.machinelearningservices",
        "microsoft.botservice", "openai", "machinelearning", "/ai/",
    ))


def _matches_any(action: str, patterns: Iterable[str]) -> bool:
    """Return True when an Azure permission pattern grants one of the wanted actions.

    Azure role actions can themselves contain wildcards, so the role action is
    treated as the glob pattern and each security-sensitive action as the target.
    """
    permission_pattern = action.lower()
    return any(fnmatch.fnmatch(pattern.lower(), permission_pattern) for pattern in patterns)


def _role_actions(role: dict[str, Any]) -> tuple[list[str], list[str], list[str], list[str]]:
    actions: list[str] = []
    not_actions: list[str] = []
    data_actions: list[str] = []
    not_data_actions: list[str] = []
    for perm in _as_list(role.get("permissions")):
        if not isinstance(perm, dict):
            continue
        actions.extend(_norm(x) for x in _as_list(perm.get("actions")) if _norm(x))
        not_actions.extend(_norm(x) for x in _as_list(perm.get("not_actions")) if _norm(x))
        data_actions.extend(_norm(x) for x in _as_list(perm.get("data_actions")) if _norm(x))
        not_data_actions.extend(_norm(x) for x in _as_list(perm.get("not_data_actions")) if _norm(x))
    return actions, not_actions, data_actions, not_data_actions


def _candidate_ai_identity(name: str, scope: str, principal_type: str) -> bool:
    n = name.lower()
    if any(k in n for k in AI_IDENTITY_KEYWORDS):
        return True
    return principal_type.lower() in {"serviceprincipal", "managedidentity"} and _is_ai_scope(scope)


@dataclass
class AzureIdentityAssessment:
    principal_id: str
    name: str
    principal_type: str
    candidate_ai_identity: bool = False
    blast_radius: str = "LOW"
    risk_points: int = 0
    finding_count: int = 0
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def add_risk(self, points: int, reason: str) -> None:
        self.risk_points = max(0, self.risk_points + points)
        if reason not in self.reasons:
            self.reasons.append(reason)

    def finalize(self, finding_count: int) -> None:
        self.finding_count = finding_count
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
            "principal_id": self.principal_id,
            "name": self.name,
            "principal_type": self.principal_type,
            "candidate_ai_identity": self.candidate_ai_identity,
            "blast_radius": self.blast_radius,
            "risk_points": min(self.risk_points, 100),
            "finding_count": self.finding_count,
            "roles": sorted(set(self.roles)),
            "scopes": sorted(set(self.scopes)),
            "reasons": self.reasons,
        }


class AzureLiveAdapter:
    """Thin read-only adapter around Azure SDK + ARM + Microsoft Graph.

    DefaultAzureCredential supports environment/service-principal credentials,
    managed identity, workload identity and Azure CLI. `credential_mode=cli`
    forces AzureCliCredential for simple local usage.
    """

    ARM = "https://management.azure.com"
    GRAPH = "https://graph.microsoft.com"

    def __init__(self, credential_mode: str = "default", tenant_id: str | None = None) -> None:
        try:
            from azure.identity import AzureCliCredential, DefaultAzureCredential  # type: ignore
            from azure.mgmt.authorization import AuthorizationManagementClient  # type: ignore
            from azure.mgmt.resource import ResourceManagementClient  # type: ignore
            from azure.mgmt.subscription import SubscriptionClient  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                'Azure scanning requires optional dependencies. Install with: '
                'pip install "agentshield-security[azure]"'
            ) from exc
        self.AuthorizationManagementClient = AuthorizationManagementClient
        self.ResourceManagementClient = ResourceManagementClient
        self.SubscriptionClient = SubscriptionClient
        if credential_mode == "cli":
            self.credential = AzureCliCredential(tenant_id=tenant_id)
        else:
            kwargs: dict[str, Any] = {"exclude_interactive_browser_credential": True}
            if tenant_id:
                kwargs["interactive_browser_tenant_id"] = tenant_id
            self.credential = DefaultAzureCredential(**kwargs)
        self._requests = __import__("requests")
        self._tenant_id = tenant_id

    def _token(self, audience: str) -> str:
        return self.credential.get_token(f"{audience}/.default").token

    def _get(self, url: str, audience: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self._requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token(audience)}"},
            params=params,
            timeout=30,
        )
        r.raise_for_status()
        return r.json() if r.content else {}

    def _post(self, url: str, audience: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self._requests.post(
            url,
            headers={"Authorization": f"Bearer {self._token(audience)}", "Content-Type": "application/json"},
            json=body,
            timeout=30,
        )
        r.raise_for_status()
        return r.json() if r.content else {}

    def _arm_get(self, path: str, versions: Iterable[str]) -> dict[str, Any]:
        last: Exception | None = None
        for version in versions:
            try:
                return self._get(f"{self.ARM}{path}", self.ARM, {"api-version": version})
            except Exception as exc:  # try stable fallbacks for provider API churn
                last = exc
        if last:
            raise last
        return {}

    def list_subscriptions(self) -> list[dict[str, Any]]:
        client = self.SubscriptionClient(self.credential)
        out = []
        for sub in client.subscriptions.list():
            out.append({
                "id": _norm(getattr(sub, "subscription_id", "")),
                "name": _norm(getattr(sub, "display_name", "")),
                "state": _norm(getattr(sub, "state", "")),
                "tenant_id": _norm(getattr(sub, "tenant_id", "")) or self._tenant_id or "",
            })
        return out

    def list_role_definitions(self, subscription_id: str) -> list[dict[str, Any]]:
        client = self.AuthorizationManagementClient(self.credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        out = []
        for rd in client.role_definitions.list(scope):
            permissions = []
            for p in getattr(rd, "permissions", None) or []:
                permissions.append({
                    "actions": list(getattr(p, "actions", None) or []),
                    "not_actions": list(getattr(p, "not_actions", None) or []),
                    "data_actions": list(getattr(p, "data_actions", None) or []),
                    "not_data_actions": list(getattr(p, "not_data_actions", None) or []),
                })
            out.append({
                "id": _norm(getattr(rd, "id", "")),
                "name": _norm(getattr(rd, "role_name", "")),
                "description": _norm(getattr(rd, "description", "")),
                "role_type": _norm(getattr(rd, "role_type", "")),
                "permissions": permissions,
            })
        return out

    def list_role_assignments(self, subscription_id: str) -> list[dict[str, Any]]:
        client = self.AuthorizationManagementClient(self.credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        out = []
        try:
            assignments = client.role_assignments.list_for_subscription()
        except AttributeError:  # compatibility with older azure-mgmt-authorization
            assignments = client.role_assignments.list_for_scope(scope)
        for ra in assignments:
            out.append({
                "id": _norm(getattr(ra, "id", "")),
                "principal_id": _norm(getattr(ra, "principal_id", "")),
                "principal_type": _norm(getattr(ra, "principal_type", "")),
                "role_definition_id": _norm(getattr(ra, "role_definition_id", "")),
                "scope": _norm(getattr(ra, "scope", "")) or scope,
                "condition": _norm(getattr(ra, "condition", "")),
                "condition_version": _norm(getattr(ra, "condition_version", "")),
            })
        return out

    def resolve_principals(self, principal_ids: list[str]) -> dict[str, dict[str, Any]]:
        resolved: dict[str, dict[str, Any]] = {}
        unique = [x for x in dict.fromkeys(principal_ids) if x]
        for i in range(0, len(unique), 1000):
            batch = unique[i:i + 1000]
            data = self._post(
                f"{self.GRAPH}/v1.0/directoryObjects/getByIds",
                self.GRAPH,
                {"ids": batch},
            )
            for obj in data.get("value", []):
                oid = _norm(obj.get("id"))
                odata = obj.get("@odata.type", "").split(".")[-1]
                resolved[oid] = {
                    "id": oid,
                    "name": _norm(obj.get("displayName")) or oid,
                    "type": odata or "DirectoryObject",
                }
        return resolved

    def list_policy_assignments(self, subscription_id: str) -> list[dict[str, Any]]:
        path = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments"
        return list(self._arm_get(path, ("2022-06-01", "2021-06-01")).get("value", []))

    def list_defender_pricings(self, subscription_id: str) -> list[dict[str, Any]]:
        path = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings"
        return list(self._arm_get(path, ("2024-01-01", "2023-01-01")).get("value", []))

    def list_diagnostic_settings(self, subscription_id: str) -> list[dict[str, Any]]:
        path = f"/subscriptions/{subscription_id}/providers/microsoft.insights/diagnosticSettings"
        return list(self._arm_get(path, ("2021-05-01-preview",)).get("value", []))

    def list_ai_resources(self, subscription_id: str) -> list[dict[str, Any]]:
        client = self.ResourceManagementClient(self.credential, subscription_id)
        out = []
        for res in client.resources.list():
            rtype = _norm(getattr(res, "type", "")).lower()
            if rtype not in AI_RESOURCE_TYPES:
                continue
            props = getattr(res, "properties", None)
            if not isinstance(props, dict):
                props = {}
            out.append({
                "id": _norm(getattr(res, "id", "")),
                "name": _norm(getattr(res, "name", "")),
                "type": _norm(getattr(res, "type", "")),
                "location": _norm(getattr(res, "location", "")),
                "properties": props,
            })
        return out


class AzureSecurityScanner:
    """Read-only Azure RBAC, Entra identity and AI-resource posture scanner."""

    def __init__(
        self,
        adapter: Any | None = None,
        credential_mode: str = "default",
        tenant_id: str | None = None,
        subscriptions: list[str] | None = None,
        principal_pattern: str | None = None,
        ai_only: bool = False,
        max_assignments: int = 1000,
    ) -> None:
        self.adapter = adapter or AzureLiveAdapter(credential_mode=credential_mode, tenant_id=tenant_id)
        self.requested_subscriptions = set(subscriptions or [])
        self.principal_pattern = principal_pattern
        self.ai_only = ai_only
        self.max_assignments = max(1, max_assignments)
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
            cwe="CWE-250" if category in {"rbac", "identity"} else None,
            owasp_llm="LLM06" if category in {"rbac", "identity", "ai-resource"} else None,
            iso27001=iso27001,
        ))

    @staticmethod
    def _role_risk(role: dict[str, Any]) -> dict[str, Any]:
        name = _norm(role.get("name"))
        lname = name.lower()
        actions, not_actions, data_actions, not_data_actions = _role_actions(role)
        all_actions = [a.lower() for a in actions]
        all_data = [a.lower() for a in data_actions]
        risk = {
            "name": name,
            "wildcard": "*" in all_actions or "*" in all_data,
            "priv_esc": any(_matches_any(a, PRIV_ESC_ACTION_PATTERNS) for a in all_actions),
            "sensitive": any(_matches_any(a, SENSITIVE_ACTION_PATTERNS) for a in all_actions + all_data),
            "broad_mutation": any(a == "*" or any(t in a for t in MUTATING_TOKENS) for a in all_actions),
            "custom": _norm(role.get("role_type")).lower() == "customrole",
            "not_actions": bool(not_actions or not_data_actions),
        }
        if lname in HIGH_PRIVILEGE_ROLES:
            risk["builtin_points"], risk["builtin_level"] = HIGH_PRIVILEGE_ROLES[lname]
        else:
            risk["builtin_points"], risk["builtin_level"] = 0, "LOW"
        return risk

    def _assess_assignment(
        self,
        sub: dict[str, Any],
        assignment: dict[str, Any],
        role: dict[str, Any],
        principal: dict[str, Any],
        identity: AzureIdentityAssessment,
    ) -> None:
        scope = _norm(assignment.get("scope")) or f"/subscriptions/{sub['id']}"
        role_name = _norm(role.get("name")) or _role_key(_norm(assignment.get("role_definition_id")))
        ptype = identity.principal_type
        is_machine = ptype.lower() in {"serviceprincipal", "managedidentity"}
        risk = self._role_risk(role)
        loc = f"azure://{sub['id']}/rbac/{identity.principal_id}"
        base_evidence = f"principal={identity.name}; type={ptype}; role={role_name}; scope={scope}"
        before = len(self.findings)

        builtin_level = risk["builtin_level"]
        if builtin_level in {"CRITICAL", "HIGH"}:
            severity = Severity.CRITICAL if builtin_level == "CRITICAL" else Severity.HIGH
            if role_name.lower() == "contributor" and not is_machine:
                severity = Severity.MEDIUM
            title = f"High-privilege Azure role: {role_name}"
            self._add(
                "AS-AZ-RBAC-001", title, severity,
                f"{identity.name} is assigned {role_name} at {_scope_level(scope).lower()} scope.",
                loc, base_evidence,
                "Reduce the assignment to the narrowest built-in/custom role and smallest resource scope. Prefer managed identity for workloads and use PIM/JIT for human privilege.",
                "rbac", "A.5.15 Access control",
            )
            identity.add_risk(risk["builtin_points"], f"{role_name} at {_scope_level(scope)} scope")

        if risk["wildcard"]:
            self._add(
                "AS-AZ-RBAC-002", "Wildcard Azure role permissions", Severity.CRITICAL,
                f"Role {role_name} grants wildcard control-plane or data-plane permissions.",
                loc, base_evidence,
                "Replace wildcard permissions with explicit actions/dataActions required by the workload.",
                "rbac", "A.5.15 Access control",
            )
            identity.add_risk(80, "Wildcard permissions")

        if risk["priv_esc"]:
            self._add(
                "AS-AZ-RBAC-003", "Azure RBAC privilege-escalation capability", Severity.CRITICAL,
                f"Role {role_name} can create/change role assignments, role definitions, elevate access, or delegate managed identities.",
                loc, base_evidence,
                "Remove Microsoft.Authorization write/elevate permissions from workload identities; isolate delegation roles and protect them with PIM and approval.",
                "rbac", "A.8.2 Privileged access rights",
            )
            identity.add_risk(90, "Can change/elevate Azure authorization")

        if risk["sensitive"]:
            self._add(
                "AS-AZ-DATA-001", "Sensitive key/secret access in Azure role", Severity.HIGH,
                f"Role {role_name} includes access to secrets, keys, storage account keys, or AI service keys.",
                loc, base_evidence,
                "Use least-privilege data-plane roles, managed identity, scoped Key Vault permissions, and disable local/key authentication on AI services where supported.",
                "rbac", "A.8.3 Information access restriction",
            )
            identity.add_risk(35, "Can access secrets/keys")

        if is_machine and _scope_level(scope) in {"SUBSCRIPTION", "MANAGEMENT_GROUP"} and (risk["builtin_points"] or risk["broad_mutation"]):
            self._add(
                "AS-AZ-RBAC-004", "Workload identity has broad Azure scope", Severity.HIGH,
                f"Machine identity {identity.name} has mutating/high-privilege access at {_scope_level(scope).lower()} scope.",
                loc, base_evidence,
                "Scope workload permissions to the specific resource group or resource required by the application/agent.",
                "identity", "A.8.2 Privileged access rights",
            )
            identity.add_risk(35, f"Machine identity at {_scope_level(scope)} scope")

        if identity.candidate_ai_identity and (risk["builtin_points"] >= 55 or risk["wildcard"] or risk["priv_esc"]):
            self._add(
                "AS-AZ-AI-001", "AI identity has excessive Azure blast radius", Severity.CRITICAL,
                f"Likely AI/agent identity {identity.name} can materially change Azure resources or authorization.",
                loc, base_evidence,
                "Create a dedicated managed identity for the AI workload, grant task-specific permissions only, add approval gates for high-impact actions, and continuously log agent activity.",
                "ai-resource", "A.8.2 Privileged access rights",
            )
            identity.add_risk(100, "AI identity can perform high-impact Azure actions")

        if assignment.get("condition"):
            identity.add_risk(-10, "RBAC condition reduces effective scope")

        identity.finding_count += len(self.findings) - before

    def _governance_checks(self, sub: dict[str, Any]) -> None:
        sid = sub["id"]
        root = f"azure://{sid}"
        try:
            policies = self.adapter.list_policy_assignments(sid)
            if not policies:
                self._add(
                    "AS-AZ-GOV-001", "No Azure Policy assignments detected", Severity.MEDIUM,
                    "No subscription-scope Azure Policy assignments were returned.", root,
                    "policyAssignments=0",
                    "Assign an appropriate governance baseline (for example Microsoft Cloud Security Benchmark initiatives) and track compliance.",
                    "governance", "A.5.36 Compliance with policies, rules and standards",
                )
        except Exception as exc:
            self._gap(f"{sid} Azure Policy", exc)

        try:
            plans = self.adapter.list_defender_pricings(sid)
            enabled = [p for p in plans if _norm((p.get("properties") or {}).get("pricingTier")).lower() == "standard"]
            if not enabled:
                self._add(
                    "AS-AZ-SEC-001", "Microsoft Defender for Cloud plans not enabled", Severity.MEDIUM,
                    "No Defender for Cloud pricing plan returned with Standard tier.", root,
                    f"plans={len(plans)}; standard=0",
                    "Review Defender for Cloud recommendations and enable the relevant Defender plans for production workloads.",
                    "monitoring", "A.8.16 Monitoring activities",
                )
        except Exception as exc:
            self._gap(f"{sid} Defender for Cloud", exc)

        try:
            diagnostics = self.adapter.list_diagnostic_settings(sid)
            if not diagnostics:
                self._add(
                    "AS-AZ-MON-001", "Subscription Activity Log export not detected", Severity.HIGH,
                    "No subscription diagnostic setting was returned for exporting Azure Activity Logs.", root,
                    "diagnosticSettings=0",
                    "Export Activity Logs to Log Analytics/Event Hub/storage and retain them according to your incident-response and compliance requirements.",
                    "monitoring", "A.8.15 Logging",
                )
        except Exception as exc:
            self._gap(f"{sid} diagnostic settings", exc)

    def _ai_resource_checks(self, sub: dict[str, Any]) -> int:
        sid = sub["id"]
        count = 0
        try:
            resources = self.adapter.list_ai_resources(sid)
        except Exception as exc:
            self._gap(f"{sid} AI resources", exc)
            return 0
        for resource in resources:
            count += 1
            props = resource.get("properties") or {}
            rtype = _norm(resource.get("type")).lower()
            loc = _norm(resource.get("id")) or f"azure://{sid}/resource/{resource.get('name')}"
            public = _norm(props.get("publicNetworkAccess"))
            disable_local = props.get("disableLocalAuth")
            if rtype == "microsoft.cognitiveservices/accounts":
                if public.lower() in {"enabled", "true"}:
                    self._add(
                        "AS-AZ-AI-010", "Azure AI account allows public network access", Severity.MEDIUM,
                        f"AI/Cognitive Services account {resource.get('name')} explicitly allows public network access.",
                        loc, f"publicNetworkAccess={public}",
                        "For sensitive workloads, use private endpoints/network ACLs and explicitly disable public network access where architecture permits.",
                        "ai-resource", "A.8.20 Networks security",
                    )
                if disable_local is False:
                    self._add(
                        "AS-AZ-AI-011", "Azure AI local/key authentication remains enabled", Severity.HIGH,
                        f"AI/Cognitive Services account {resource.get('name')} reports disableLocalAuth=false.",
                        loc, f"disableLocalAuth={disable_local!r}",
                        "Prefer Microsoft Entra ID + managed identity and disable local/key authentication where supported by the workload.",
                        "ai-resource", "A.5.17 Authentication information",
                    )
                if not props:
                    self._gap(f"{loc} AI resource properties", RuntimeError("resource properties were not returned by Azure inventory API"))
            elif rtype == "microsoft.machinelearningservices/workspaces":
                if public.lower() in {"enabled", "true"}:
                    self._add(
                        "AS-AZ-AI-012", "Azure ML workspace public network exposure", Severity.MEDIUM,
                        f"Azure ML workspace {resource.get('name')} explicitly allows public network access.",
                        loc, f"publicNetworkAccess={public}",
                        "Use managed virtual networks/private endpoints and limit workspace access to approved networks for sensitive workloads.",
                        "ai-resource", "A.8.20 Networks security",
                    )
                if not props:
                    self._gap(f"{loc} Azure ML properties", RuntimeError("resource properties were not returned by Azure inventory API"))
        return count

    def scan(self) -> ScanResult:
        try:
            subscriptions = self.adapter.list_subscriptions()
        except Exception as exc:
            raise RuntimeError(f"Unable to enumerate Azure subscriptions: {exc}") from exc
        if self.requested_subscriptions:
            subscriptions = [s for s in subscriptions if s.get("id") in self.requested_subscriptions]
        if not subscriptions:
            requested = ", ".join(sorted(self.requested_subscriptions)) or "current identity"
            raise RuntimeError(f"No accessible Azure subscriptions found for {requested}.")

        metadata_subs: list[dict[str, Any]] = []
        assessments: dict[str, AzureIdentityAssessment] = {}
        total_assignments = 0
        total_ai_resources = 0
        tenant_ids: set[str] = set()

        # Enumerate first, then resolve all principals in one Graph batch where possible.
        subscription_data: list[tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, Any]]]] = []
        principal_ids: list[str] = []
        for sub in subscriptions:
            sid = _norm(sub.get("id"))
            if not sid:
                continue
            if sub.get("tenant_id"):
                tenant_ids.add(_norm(sub.get("tenant_id")))
            try:
                roles = self.adapter.list_role_definitions(sid)
                role_map = {_role_key(_norm(r.get("id"))): r for r in roles}
            except Exception as exc:
                self._gap(f"{sid} role definitions", exc)
                role_map = {}
            try:
                assignments = self.adapter.list_role_assignments(sid)[: self.max_assignments]
            except Exception as exc:
                self._gap(f"{sid} role assignments", exc)
                assignments = []
            principal_ids.extend(_norm(a.get("principal_id")) for a in assignments if _norm(a.get("principal_id")))
            subscription_data.append((sub, role_map, assignments))

        try:
            principals = self.adapter.resolve_principals(principal_ids)
        except Exception as exc:
            principals = {}
            self._gap("Microsoft Graph principal enrichment", exc)

        for sub, role_map, assignments in subscription_data:
            sid = _norm(sub.get("id"))
            included = 0
            for assignment in assignments:
                pid = _norm(assignment.get("principal_id"))
                p = principals.get(pid, {})
                ptype = _norm(p.get("type")) or _norm(assignment.get("principal_type")) or "Unknown"
                pname = _norm(p.get("name")) or pid or "Unknown principal"
                scope = _norm(assignment.get("scope")) or f"/subscriptions/{sid}"
                candidate = _candidate_ai_identity(pname, scope, ptype)
                if self.principal_pattern and not fnmatch.fnmatch(pname.lower(), self.principal_pattern.lower()):
                    continue
                if self.ai_only and not candidate:
                    continue
                role = role_map.get(_role_key(_norm(assignment.get("role_definition_id"))), {
                    "id": assignment.get("role_definition_id"),
                    "name": _role_key(_norm(assignment.get("role_definition_id"))),
                    "permissions": [],
                })
                identity = assessments.get(pid)
                if identity is None:
                    identity = AzureIdentityAssessment(pid, pname, ptype, candidate)
                    assessments[pid] = identity
                else:
                    identity.candidate_ai_identity = identity.candidate_ai_identity or candidate
                identity.roles.append(_norm(role.get("name")))
                identity.scopes.append(scope)
                self._assess_assignment(sub, assignment, role, p, identity)
                included += 1
                total_assignments += 1
            self._governance_checks(sub)
            ai_count = self._ai_resource_checks(sub)
            total_ai_resources += ai_count
            metadata_subs.append({
                "id": sid,
                "name": _norm(sub.get("name")),
                "state": _norm(sub.get("state")),
                "tenant_id": _norm(sub.get("tenant_id")),
                "assignments_scanned": included,
                "ai_resources_scanned": ai_count,
            })

        # If a principal could not be resolved, surface that as an evidence quality issue.
        for pid, identity in assessments.items():
            if identity.name == pid and identity.principal_type == "Unknown":
                self._add(
                    "AS-AZ-ENTRA-001", "Azure RBAC principal could not be resolved", Severity.MEDIUM,
                    "The role assignment principal could not be enriched from Microsoft Graph.",
                    f"azure://directoryObjects/{pid}", f"principalId={pid}",
                    "Grant the scanner sufficient read-only directory visibility or review the object manually to rule out orphaned/unknown privileged assignments.",
                    "identity", "A.5.16 Identity management",
                )
                identity.add_risk(15, "Unresolved directory object")
                identity.finding_count += 1
            identity.finalize(identity.finding_count)

        ordered = sorted(assessments.values(), key=lambda x: (-min(x.risk_points, 100), x.name.lower()))
        return ScanResult(
            root="azure://subscriptions",
            findings=self.findings,
            files_scanned=total_assignments,
            metadata={
                "provider": "azure",
                "tenant_ids": sorted(x for x in tenant_ids if x),
                "subscriptions": metadata_subs,
                "identity_assessments": [x.to_dict() for x in ordered],
                "ai_resources_scanned": total_ai_resources,
                "visibility_gaps": self.visibility_gaps,
            },
        )
