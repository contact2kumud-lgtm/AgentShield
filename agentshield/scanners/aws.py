from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import unquote

from ..models import Finding, ScanResult, Severity


AI_ROLE_KEYWORDS = (
    "agent", "bedrock", "sagemaker", "genai", "llm", "model", "assistant",
    "copilot", "chatbot", "bot", "rag", "ai-", "-ai", "lambda"
)
AI_SERVICE_PRINCIPALS = {
    "bedrock.amazonaws.com",
    "bedrock-agentcore.amazonaws.com",
    "sagemaker.amazonaws.com",
}
PRIV_ESC_ACTIONS = {
    "iam:passrole",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:updateassumerolepolicy",
    "iam:createaccesskey",
    "sts:assumerole",
    "lambda:updatefunctioncode",
    "lambda:updatefunctionconfiguration",
}
SENSITIVE_READ_ACTIONS = {
    "secretsmanager:getsecretvalue",
    "ssm:getparameter",
    "ssm:getparameters",
    "ssm:getparametersbypath",
    "kms:decrypt",
    "s3:getobject",
    "dynamodb:getitem",
    "dynamodb:scan",
    "dynamodb:query",
}
DESTRUCTIVE_PREFIXES = (
    "s3:delete", "iam:delete", "kms:schedulekeydeletion", "ec2:terminate",
    "rds:delete", "dynamodb:delete", "lambda:delete", "cloudformation:delete",
)
MUTATING_VERBS = (
    "put", "create", "update", "delete", "start", "stop", "send", "publish",
    "invoke", "execute", "run", "write", "modify", "attach", "detach", "associate",
    "disassociate", "set", "enable", "disable", "terminate", "reboot", "restore",
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _policy_doc(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    candidates = (value, unquote(value))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            continue
    return {}


def _actions(statement: dict[str, Any]) -> list[str]:
    return [str(a).strip() for a in _as_list(statement.get("Action"))]


def _resources(statement: dict[str, Any]) -> list[str]:
    return [str(r).strip() for r in _as_list(statement.get("Resource"))]


def _action_matches(action: str, wanted: Iterable[str]) -> bool:
    action_l = action.lower()
    return any(fnmatch.fnmatch(action_l, pattern.lower()) or fnmatch.fnmatch(pattern.lower(), action_l) for pattern in wanted)


def _is_allow(statement: dict[str, Any]) -> bool:
    return str(statement.get("Effect", "Allow")).lower() == "allow"


def _is_mutating_action(action: str) -> bool:
    if ":" not in action:
        return False
    verb = action.split(":", 1)[1].lower().replace("*", "")
    return any(verb.startswith(prefix) for prefix in MUTATING_VERBS)


def _trust_principals(doc: dict[str, Any]) -> tuple[set[str], set[str]]:
    aws: set[str] = set()
    services: set[str] = set()
    for st in _as_list(doc.get("Statement")):
        if not isinstance(st, dict) or not _is_allow(st):
            continue
        principal = st.get("Principal")
        if principal == "*":
            aws.add("*")
            continue
        if not isinstance(principal, dict):
            continue
        aws.update(str(x) for x in _as_list(principal.get("AWS")))
        services.update(str(x) for x in _as_list(principal.get("Service")))
    return aws, services


@dataclass
class RoleAssessment:
    name: str
    arn: str
    candidate_ai_role: bool
    blast_radius: str = "LOW"
    risk_points: int = 0
    finding_count: int = 0
    reasons: list[str] = field(default_factory=list)
    trusted_services: list[str] = field(default_factory=list)
    attached_policies: list[str] = field(default_factory=list)

    def add_risk(self, points: int, reason: str) -> None:
        self.risk_points += points
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
            "name": self.name,
            "arn": self.arn,
            "candidate_ai_role": self.candidate_ai_role,
            "blast_radius": self.blast_radius,
            "risk_points": min(self.risk_points, 100),
            "finding_count": self.finding_count,
            "reasons": self.reasons,
            "trusted_services": self.trusted_services,
            "attached_policies": self.attached_policies,
        }


class AwsSecurityScanner:
    """Read-only AWS security and IAM blast-radius scanner.

    The scanner never performs mutating AWS API calls. A boto3 Session may be injected
    for testing or embedding; otherwise one is created from the requested profile/region.
    """

    def __init__(
        self,
        profile: str | None = None,
        region: str | None = None,
        session: Any | None = None,
        role_pattern: str | None = None,
        ai_only: bool = False,
        max_roles: int = 250,
    ) -> None:
        if session is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - exercised by users without optional dependency
                raise RuntimeError(
                    'AWS scanning requires boto3. Install with: pip install "agentshield-security[aws]"'
                ) from exc
            session = boto3.Session(profile_name=profile, region_name=region)
        self.session = session
        self.region = region or getattr(session, "region_name", None) or "us-east-1"
        self.role_pattern = role_pattern
        self.ai_only = ai_only
        self.max_roles = max(1, max_roles)
        self.findings: list[Finding] = []
        self.visibility_gaps: list[str] = []

    def _client(self, service: str, region: str | None = None) -> Any:
        kwargs = {"region_name": region} if region else {}
        return self.session.client(service, **kwargs)

    def _visibility_gap(self, control: str, exc: Exception) -> None:
        msg = f"{control}: {exc.__class__.__name__}"
        if msg not in self.visibility_gaps:
            self.visibility_gaps.append(msg)

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
            rule_id, title, severity, message, location, 1, evidence[:300], remediation,
            category, "CWE-250" if category == "iam" else None, "LLM06" if category == "iam" else None,
            iso27001,
        ))

    def _list_iam(self, client: Any, method: str, result_key: str, **kwargs: Any) -> list[Any]:
        out: list[Any] = []
        marker: str | None = None
        while True:
            call_kwargs = dict(kwargs)
            if marker:
                call_kwargs["Marker"] = marker
            response = getattr(client, method)(**call_kwargs)
            out.extend(response.get(result_key, []))
            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")
            if not marker:
                break
        return out

    def _role_is_candidate(self, role: dict[str, Any], services: set[str]) -> bool:
        name_path = f"{role.get('Path', '')}{role.get('RoleName', '')}".lower()
        keyword_match = any(k in name_path for k in AI_ROLE_KEYWORDS)
        service_match = bool(services.intersection(AI_SERVICE_PRINCIPALS))
        pattern_match = True if not self.role_pattern else fnmatch.fnmatch(role.get("RoleName", ""), self.role_pattern)
        return pattern_match and (keyword_match or service_match)

    def _analyze_trust(self, role: dict[str, Any], assessment: RoleAssessment, account_id: str) -> None:
        doc = _policy_doc(role.get("AssumeRolePolicyDocument"))
        aws_principals, service_principals = _trust_principals(doc)
        assessment.trusted_services = sorted(service_principals)
        loc = f"aws://iam/role/{role.get('RoleName', 'unknown')}/trust"

        if "*" in aws_principals or "*" in service_principals:
            self._add(
                "AS-AWS-IAM-001", "Role trust policy allows any principal", Severity.CRITICAL,
                "The role trust policy contains Principal '*', allowing an unbounded trust relationship.", loc,
                "Principal: *", "Restrict the trust policy to exact workload/service principals and enforce conditions.",
                "iam", "A.5.15",
            )
            assessment.add_risk(55, "Unbounded role trust")

        for principal in sorted(aws_principals - {"*"}):
            m = re.match(r"arn:[^:]+:iam::(\d{12}):", principal)
            if m and m.group(1) != account_id:
                statements = _as_list(doc.get("Statement"))
                has_external_id = any(
                    isinstance(st, dict) and "sts:ExternalId" in json.dumps(st.get("Condition", {}))
                    for st in statements
                )
                severity = Severity.MEDIUM if has_external_id else Severity.HIGH
                self._add(
                    "AS-AWS-IAM-002", "Cross-account role trust", severity,
                    f"Role trusts principal from external AWS account {m.group(1)}.", loc, principal,
                    "Validate the external account, scope the principal precisely, and require sts:ExternalId where appropriate.",
                    "iam", "A.5.19",
                )
                assessment.add_risk(18 if has_external_id else 30, "Cross-account trust")

    def _analyze_policy(
        self,
        role_name: str,
        policy_name: str,
        policy_doc: dict[str, Any],
        assessment: RoleAssessment,
        policy_arn: str | None = None,
    ) -> None:
        loc = f"aws://iam/role/{role_name}/policy/{policy_name}"
        managed_name = (policy_arn or "").split("/")[-1]
        if managed_name == "AdministratorAccess":
            self._add(
                "AS-AWS-IAM-010", "AdministratorAccess attached to workload role", Severity.CRITICAL,
                "The role has the AWS managed AdministratorAccess policy attached.", loc,
                policy_arn or policy_name,
                "Replace AdministratorAccess with a dedicated least-privilege policy containing only required actions and resources.",
                "iam", "A.5.15",
            )
            assessment.add_risk(70, "AdministratorAccess")
        elif managed_name in {"PowerUserAccess", "IAMFullAccess"}:
            self._add(
                "AS-AWS-IAM-011", f"Broad managed policy attached: {managed_name}", Severity.HIGH,
                "A broad AWS managed policy is attached to the workload role.", loc,
                policy_arn or policy_name,
                "Replace broad managed access with a workload-specific least-privilege policy.", "iam", "A.5.15",
            )
            assessment.add_risk(35, managed_name)

        for index, statement in enumerate(_as_list(policy_doc.get("Statement")), 1):
            if not isinstance(statement, dict) or not _is_allow(statement):
                continue
            actions = _actions(statement)
            resources = _resources(statement)
            action_l = [a.lower() for a in actions]
            wildcard_resource = not resources or "*" in resources
            evidence = f"Statement {index}: Action={actions or ['<NotAction>']} Resource={resources or ['*']}"

            if "NotAction" in statement:
                self._add(
                    "AS-AWS-IAM-012", "Allow statement uses NotAction", Severity.HIGH,
                    "An Allow statement uses NotAction, which can unintentionally grant very broad privileges.", loc,
                    evidence, "Replace Allow+NotAction with an explicit allowlist of required actions.", "iam", "A.5.15",
                )
                assessment.add_risk(35, "Allow + NotAction")

            if any(a == "*" or a == "*:*" for a in action_l):
                self._add(
                    "AS-AWS-IAM-013", "Wildcard AWS action", Severity.CRITICAL,
                    "Policy grants all AWS actions.", loc, evidence,
                    "Replace Action '*' with the exact actions the AI workload requires.", "iam", "A.5.15",
                )
                assessment.add_risk(65, "Wildcard Action")
                continue

            broad_service = [a for a in action_l if a.endswith(":*")]
            if broad_service:
                sev = Severity.HIGH if wildcard_resource else Severity.MEDIUM
                self._add(
                    "AS-AWS-IAM-014", "Service-wide wildcard permission", sev,
                    "Policy grants every action for one or more AWS services.", loc,
                    evidence, "Replace service wildcards with exact API actions and scope resources wherever supported.",
                    "iam", "A.5.15",
                )
                assessment.add_risk(28 if wildcard_resource else 16, "Service-wide wildcard")

            priv = sorted({a for a in action_l if _action_matches(a, PRIV_ESC_ACTIONS)})
            if priv:
                passrole_star = "iam:passrole" in priv and wildcard_resource
                sev = Severity.CRITICAL if passrole_star else Severity.HIGH
                self._add(
                    "AS-AWS-IAM-015", "Privilege-escalation capable permission", sev,
                    "Role can perform actions commonly involved in AWS privilege escalation or role chaining.", loc,
                    f"{evidence}; matched={priv}",
                    "Remove privilege-escalation actions where possible. Scope iam:PassRole/sts:AssumeRole to exact approved role ARNs and conditions.",
                    "iam", "A.5.18",
                )
                assessment.add_risk(48 if passrole_star else 32, "Privilege escalation path")

            sensitive = sorted({a for a in action_l if _action_matches(a, SENSITIVE_READ_ACTIONS)})
            if sensitive and wildcard_resource:
                self._add(
                    "AS-AWS-DATA-001", "Broad sensitive-data read access", Severity.HIGH,
                    "Workload can read secrets, decrypt data, or access data using wildcard resources.", loc,
                    f"{evidence}; matched={sensitive}",
                    "Scope data and secret access to exact ARNs. Separate retrieval roles and use resource policies/conditions where possible.",
                    "data", "A.8.3",
                )
                assessment.add_risk(30, "Broad sensitive-data access")

            destructive = sorted({a for a in action_l if any(a.startswith(prefix) for prefix in DESTRUCTIVE_PREFIXES)})
            if destructive and wildcard_resource:
                self._add(
                    "AS-AWS-IAM-016", "Broad destructive permission", Severity.HIGH,
                    "Role has destructive permissions against wildcard resources.", loc,
                    f"{evidence}; matched={destructive}",
                    "Scope destructive actions to exact resources and place high-impact operations behind approval controls.",
                    "iam", "A.8.18",
                )
                assessment.add_risk(30, "Broad destructive access")

            mutating = sorted({a for a in action_l if _is_mutating_action(a)})
            already_high_risk = set(priv) | set(destructive)
            other_mutating = [a for a in mutating if a not in already_high_risk]
            if other_mutating and wildcard_resource:
                self._add(
                    "AS-AWS-IAM-017", "Wildcard-resource mutating access", Severity.HIGH,
                    "Role can perform state-changing actions against wildcard resources.", loc,
                    f"{evidence}; matched={other_mutating}",
                    "Scope mutating actions to exact resource ARNs and require approval for high-impact agent operations.",
                    "iam", "A.8.18",
                )
                assessment.add_risk(24, "Broad mutating access")

    def _scan_roles(self, iam: Any, account_id: str) -> tuple[list[RoleAssessment], int]:
        roles = self._list_iam(iam, "list_roles", "Roles")[: self.max_roles]
        assessments: list[RoleAssessment] = []
        scanned = 0
        for role in roles:
            role_name = role.get("RoleName", "unknown")
            trust = _policy_doc(role.get("AssumeRolePolicyDocument"))
            _, services = _trust_principals(trust)
            candidate = self._role_is_candidate(role, services)
            if self.role_pattern and not fnmatch.fnmatch(role_name, self.role_pattern):
                continue
            if self.ai_only and not candidate:
                continue
            scanned += 1
            assessment = RoleAssessment(role_name, role.get("Arn", f"arn:aws:iam::{account_id}:role/{role_name}"), candidate)
            start_findings = len(self.findings)
            self._analyze_trust(role, assessment, account_id)

            try:
                attached = self._list_iam(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name)
            except Exception as exc:
                self._visibility_gap(f"IAM attached policies for {role_name}", exc)
                attached = []
            assessment.attached_policies = [p.get("PolicyName", "") for p in attached]
            for policy in attached:
                arn = policy.get("PolicyArn")
                name = policy.get("PolicyName", arn or "managed")
                doc: dict[str, Any] = {}
                try:
                    meta = iam.get_policy(PolicyArn=arn)["Policy"]
                    version = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])["PolicyVersion"]
                    doc = _policy_doc(version.get("Document"))
                except Exception as exc:
                    self._visibility_gap(f"IAM managed policy {name}", exc)
                self._analyze_policy(role_name, name, doc, assessment, arn)

            try:
                inline_names = self._list_iam(iam, "list_role_policies", "PolicyNames", RoleName=role_name)
            except Exception as exc:
                self._visibility_gap(f"IAM inline policies for {role_name}", exc)
                inline_names = []
            for name in inline_names:
                try:
                    doc = _policy_doc(iam.get_role_policy(RoleName=role_name, PolicyName=name).get("PolicyDocument"))
                    self._analyze_policy(role_name, name, doc, assessment)
                except Exception as exc:
                    self._visibility_gap(f"IAM inline policy {role_name}/{name}", exc)

            assessment.finalize(len(self.findings) - start_findings)
            assessments.append(assessment)
        assessments.sort(key=lambda x: (-x.risk_points, x.name.lower()))
        return assessments, scanned

    def _scan_account_controls(self, account_id: str) -> None:
        # Root MFA / IAM account summary
        try:
            summary = self._client("iam").get_account_summary().get("SummaryMap", {})
            if int(summary.get("AccountMFAEnabled", 0)) != 1:
                self._add(
                    "AS-AWS-ACC-001", "Root account MFA not enabled", Severity.CRITICAL,
                    "AWS account summary indicates that root-user MFA is not enabled.", "aws://account/root",
                    f"AccountMFAEnabled={summary.get('AccountMFAEnabled', 0)}",
                    "Enable phishing-resistant MFA for the AWS root user and avoid routine root-user access.",
                    "identity", "A.5.17",
                )
        except Exception as exc:
            self._visibility_gap("IAM account summary", exc)

        # CloudTrail
        try:
            cloudtrail = self._client("cloudtrail", self.region)
            trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
            logging = []
            for trail in trails:
                try:
                    status = cloudtrail.get_trail_status(Name=trail.get("TrailARN") or trail.get("Name"))
                    logging.append(bool(status.get("IsLogging")))
                except Exception as exc:
                    self._visibility_gap(f"CloudTrail status {trail.get('Name', '')}", exc)
            if not trails or not any(logging):
                self._add(
                    "AS-AWS-LOG-001", "No active CloudTrail trail detected", Severity.HIGH,
                    "No active account trail was found in the selected AWS region.", "aws://cloudtrail",
                    f"region={self.region}; trails={len(trails)}",
                    "Enable an organization/account CloudTrail with management events, log-file validation, encryption, and protected centralized storage.",
                    "audit", "A.8.15",
                )
            elif not any(bool(t.get("IsMultiRegionTrail")) for t in trails):
                self._add(
                    "AS-AWS-LOG-002", "CloudTrail is not multi-region", Severity.MEDIUM,
                    "Active CloudTrail configuration does not include a multi-region trail.", "aws://cloudtrail",
                    f"region={self.region}", "Use a multi-region trail so management activity is captured across enabled regions.",
                    "audit", "A.8.15",
                )
        except Exception as exc:
            self._visibility_gap("CloudTrail", exc)

        # GuardDuty
        try:
            gd = self._client("guardduty", self.region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                self._add(
                    "AS-AWS-DET-001", "GuardDuty not enabled", Severity.HIGH,
                    "No Amazon GuardDuty detector exists in the selected region.", f"aws://guardduty/{self.region}",
                    f"region={self.region}", "Enable GuardDuty in all actively used regions and centralize findings where possible.",
                    "detection", "A.8.16",
                )
        except Exception as exc:
            self._visibility_gap("GuardDuty", exc)

        # AWS Config
        try:
            cfg = self._client("config", self.region)
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            recording = any(bool(s.get("recording")) for s in statuses)
            if not recorders or not recording:
                self._add(
                    "AS-AWS-CFG-001", "AWS Config recording not active", Severity.MEDIUM,
                    "AWS Config does not appear to be actively recording resources in the selected region.",
                    f"aws://config/{self.region}", f"recorders={len(recorders)}; recording={recording}",
                    "Enable AWS Config recording for required resource types and aggregate compliance centrally.",
                    "configuration", "A.8.9",
                )
        except Exception as exc:
            self._visibility_gap("AWS Config", exc)

        # Account-level S3 public access block
        try:
            s3c = self._client("s3control", self.region)
            pab = s3c.get_public_access_block(AccountId=account_id).get("PublicAccessBlockConfiguration", {})
            required = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            missing = [k for k in required if not pab.get(k)]
            if missing:
                self._add(
                    "AS-AWS-S3-001", "Account-level S3 public access block incomplete", Severity.HIGH,
                    "One or more account-level S3 public-access-block settings are disabled.", "aws://s3/account-public-access-block",
                    f"disabled={missing}", "Enable all four account-level S3 Block Public Access controls unless a documented exception requires otherwise.",
                    "data", "A.8.3",
                )
        except Exception as exc:
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            if code == "NoSuchPublicAccessBlockConfiguration":
                self._add(
                    "AS-AWS-S3-001", "Account-level S3 public access block not configured", Severity.HIGH,
                    "No account-level S3 Public Access Block configuration was found.", "aws://s3/account-public-access-block",
                    "NoSuchPublicAccessBlockConfiguration",
                    "Enable all four account-level S3 Block Public Access controls unless a documented exception requires otherwise.",
                    "data", "A.8.3",
                )
            else:
                self._visibility_gap("S3 account public access block", exc)

        # EBS default encryption
        try:
            ec2 = self._client("ec2", self.region)
            enabled = bool(ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
            if not enabled:
                self._add(
                    "AS-AWS-ENC-001", "EBS encryption by default disabled", Severity.MEDIUM,
                    "New EBS volumes are not encrypted by default in the selected region.", f"aws://ec2/{self.region}/ebs",
                    "EbsEncryptionByDefault=false", "Enable EBS encryption by default and define an approved KMS key strategy.",
                    "encryption", "A.8.24",
                )
        except Exception as exc:
            self._visibility_gap("EBS default encryption", exc)

        # Security Hub
        try:
            sh = self._client("securityhub", self.region)
            sh.describe_hub()
        except Exception as exc:
            # AccessDenied means we cannot conclude disabled; other common errors may indicate not enabled.
            text = str(exc).lower()
            if "not subscribed" in text or "invalidaccess" in text or "resource not found" in text:
                self._add(
                    "AS-AWS-SEC-001", "AWS Security Hub not enabled", Severity.MEDIUM,
                    "Security Hub does not appear to be enabled in the selected region.", f"aws://securityhub/{self.region}",
                    f"region={self.region}", "Enable Security Hub and an appropriate security standard to centralize cloud posture findings.",
                    "detection", "A.8.16",
                )
            else:
                self._visibility_gap("Security Hub", exc)

    def scan(self) -> ScanResult:
        self.findings = []
        self.visibility_gaps = []
        try:
            identity = self._client("sts").get_caller_identity()
        except Exception as exc:
            raise RuntimeError(f"Unable to authenticate to AWS using the supplied credentials/profile: {exc}") from exc

        account_id = str(identity.get("Account", "unknown"))
        principal_arn = str(identity.get("Arn", "unknown"))
        try:
            assessments, scanned = self._scan_roles(self._client("iam"), account_id)
        except Exception as exc:
            raise RuntimeError(f"Unable to enumerate IAM roles. Grant read-only IAM visibility: {exc}") from exc

        self._scan_account_controls(account_id)

        if self.visibility_gaps:
            self._add(
                "AS-AWS-VIS-001", "AWS assessment visibility is incomplete", Severity.MEDIUM,
                "One or more read-only AWS APIs could not be queried, so the assessment may be incomplete.",
                "aws://scanner/visibility", "; ".join(self.visibility_gaps[:8]),
                "Grant the AgentShield scanner the documented read-only permissions, then rerun the assessment.",
                "visibility", "A.5.36",
            )

        self.findings.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value], f.file, f.rule_id))
        metadata = {
            "provider": "aws",
            "account_id": account_id,
            "principal_arn": principal_arn,
            "region": self.region,
            "ai_only": self.ai_only,
            "role_pattern": self.role_pattern,
            "role_assessments": [a.to_dict() for a in assessments],
            "visibility_gaps": self.visibility_gaps,
        }
        return ScanResult(f"aws://{account_id}", self.findings, scanned, metadata=metadata)
