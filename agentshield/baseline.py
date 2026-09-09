from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ScanResult


def _finding_key(f: dict[str, Any]) -> tuple[str, str, str]:
    return (str(f.get("rule_id", "")), str(f.get("file", "")), str(f.get("title", "")))


def result_payload(result: ScanResult) -> dict[str, Any]:
    return {
        "summary": result.summary(),
        "metadata": result.metadata,
        "findings": [f.to_dict() for f in result.findings],
    }


def write_baseline(result: ScanResult, path: str) -> None:
    Path(path).write_text(json.dumps(result_payload(result), indent=2), encoding="utf-8")


def compare_payloads(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_findings = {_finding_key(f): f for f in old.get("findings", [])}
    new_findings = {_finding_key(f): f for f in new.get("findings", [])}
    new_keys = sorted(set(new_findings) - set(old_findings))
    resolved_keys = sorted(set(old_findings) - set(new_findings))
    persistent_keys = sorted(set(old_findings) & set(new_findings))
    old_score = int(old.get("summary", {}).get("score", 0))
    new_score = int(new.get("summary", {}).get("score", 0))
    return {
        "old_score": old_score,
        "new_score": new_score,
        "score_delta": new_score - old_score,
        "new_findings": [new_findings[k] for k in new_keys],
        "resolved_findings": [old_findings[k] for k in resolved_keys],
        "persistent_findings": [new_findings[k] for k in persistent_keys],
    }


def compare_baseline_file(path: str, result: ScanResult) -> dict[str, Any]:
    old = json.loads(Path(path).read_text(encoding="utf-8"))
    return compare_payloads(old, result_payload(result))


def format_diff(diff: dict[str, Any]) -> str:
    sign = "+" if diff["score_delta"] >= 0 else ""
    lines = [
        f"Baseline diff | score {diff['old_score']} -> {diff['new_score']} ({sign}{diff['score_delta']})",
        f"New findings: {len(diff['new_findings'])} | Resolved: {len(diff['resolved_findings'])} | Persistent: {len(diff['persistent_findings'])}",
    ]
    for f in diff["new_findings"][:20]:
        lines.append(f"  + [{f.get('severity')}] {f.get('rule_id')} {f.get('title')} @ {f.get('file')}")
    for f in diff["resolved_findings"][:20]:
        lines.append(f"  - [{f.get('severity')}] {f.get('rule_id')} {f.get('title')} @ {f.get('file')}")
    return "\n".join(lines)
