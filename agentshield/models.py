from __future__ import annotations
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any

class Severity(str, Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'

WEIGHTS = {Severity.CRITICAL: 30, Severity.HIGH: 18, Severity.MEDIUM: 9, Severity.LOW: 3, Severity.INFO: 0}

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    file: str
    line: int = 1
    evidence: str = ''
    remediation: str = ''
    category: str = 'general'
    cwe: str | None = None
    owasp_llm: str | None = None
    iso27001: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d

@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    files_scanned: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        deduction = sum(WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - deduction)

    @property
    def risk_level(self) -> str:
        if any(f.severity == Severity.CRITICAL for f in self.findings) or self.score < 40:
            return 'CRITICAL'
        if self.score < 65:
            return 'HIGH'
        if self.score < 85:
            return 'MEDIUM'
        return 'LOW'

    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        result = {'root': self.root, 'score': self.score, 'risk_level': self.risk_level,
                  'files_scanned': self.files_scanned, 'findings': len(self.findings), 'severity': counts}
        if self.metadata.get('provider'):
            result['provider'] = self.metadata['provider']
        return result
