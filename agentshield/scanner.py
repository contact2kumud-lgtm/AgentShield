from __future__ import annotations
from pathlib import Path
from .models import ScanResult
from .scanners.source import SourceScanner
from .scanners.supply_chain import SupplyChainScanner
from .scanners.github_actions import GitHubActionsScanner

class AgentShieldScanner:
    def scan(self, root: str | Path) -> ScanResult:
        root = Path(root).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f'Not a directory: {root}')
        findings, files = SourceScanner().scan(root)
        findings += SupplyChainScanner().scan(root)
        findings += GitHubActionsScanner().scan(root)
        findings.sort(key=lambda f: ({'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}[f.severity.value], f.file, f.line))
        return ScanResult(str(root), findings, files)
