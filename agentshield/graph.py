from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .models import ScanResult


def _id(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", text)
    return cleaned[:80] or "node"


def _label(text: Any) -> str:
    return str(text or "").replace('"', "'")[:120]


def build_mermaid(result: ScanResult) -> str:
    provider = result.metadata.get("provider")
    lines = ["flowchart LR", '  ROOT["AgentShield Blast Radius"]']
    if provider == "aws":
        account = _id("aws_" + str(result.metadata.get("account_id", "account")))
        lines += [f'  {account}["AWS Account\\n{_label(result.metadata.get("account_id"))}"]', f"  ROOT --> {account}"]
        for idx, role in enumerate(result.metadata.get("role_assessments", [])[:40]):
            r = _id(f"role_{idx}_{role.get('name')}")
            lines.append(f'  {r}["{_label(role.get("name"))}\\n{_label(role.get("blast_radius"))}"]')
            lines.append(f"  {account} --> {r}")
            for pidx, policy in enumerate(role.get("attached_policies", [])[:6]):
                p = _id(f"policy_{idx}_{pidx}_{policy}")
                lines.append(f'  {p}["Policy\\n{_label(policy)}"]')
                lines.append(f"  {r} --> {p}")
            for sidx, svc in enumerate(role.get("trusted_services", [])[:4]):
                s = _id(f"svc_{idx}_{sidx}_{svc}")
                lines.append(f'  {s}["Trust\\n{_label(svc)}"]')
                lines.append(f"  {s} --> {r}")
    elif provider == "azure":
        root = "AZURE"
        lines += ['  AZURE["Microsoft Azure"]', "  ROOT --> AZURE"]
        for idx, ident in enumerate(result.metadata.get("identity_assessments", [])[:40]):
            n = _id(f"azid_{idx}_{ident.get('name')}")
            lines.append(f'  {n}["{_label(ident.get("name"))}\\n{_label(ident.get("blast_radius"))}"]')
            lines.append(f"  {root} --> {n}")
            for ridx, role in enumerate(ident.get("roles", [])[:6]):
                r = _id(f"azrole_{idx}_{ridx}_{role}")
                lines.append(f'  {r}["Role\\n{_label(role)}"]')
                lines.append(f"  {n} --> {r}")
    elif provider == "gcp":
        lines += ['  GCP["Google Cloud"]', "  ROOT --> GCP"]
        for idx, ident in enumerate(result.metadata.get("identity_assessments", [])[:40]):
            n = _id(f"gcpid_{idx}_{ident.get('name')}")
            lines.append(f'  {n}["{_label(ident.get("name"))}\\n{_label(ident.get("blast_radius"))}"]')
            lines.append(f"  GCP --> {n}")
            for ridx, role in enumerate(ident.get("roles", [])[:6]):
                r = _id(f"gcprole_{idx}_{ridx}_{role}")
                lines.append(f'  {r}["Role\\n{_label(role)}"]')
                lines.append(f"  {n} --> {r}")
            for pidx, project in enumerate(ident.get("projects", [])[:4]):
                p = _id(f"gcpproj_{idx}_{pidx}_{project}")
                lines.append(f'  {p}["Project\\n{_label(project)}"]')
                lines.append(f"  {n} --> {p}")
    else:
        lines += ['  REPO["Repository"]', "  ROOT --> REPO"]
        for idx, finding in enumerate(result.findings[:40]):
            f = _id(f"finding_{idx}_{finding.rule_id}")
            lines.append(f'  {f}["{_label(finding.severity.value)}\\n{_label(finding.title)}"]')
            lines.append(f"  REPO --> {f}")
    return "\n".join(lines) + "\n"


def write_mermaid(result: ScanResult, path: str) -> None:
    Path(path).write_text(build_mermaid(result), encoding="utf-8")
