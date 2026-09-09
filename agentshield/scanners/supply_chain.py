from __future__ import annotations
import json
from pathlib import Path
from ..models import Finding, Severity

class SupplyChainScanner:
    def scan(self, root: Path) -> list[Finding]:
        out: list[Finding] = []
        req = root / 'requirements.txt'
        if req.exists():
            for i, raw in enumerate(req.read_text(errors='ignore').splitlines(),1):
                s = raw.strip()
                if not s or s.startswith('#') or s.startswith('-'):
                    continue
                if not any(op in s for op in ('==','@ git+','@ https://')):
                    out.append(Finding('AS-SC-001','Unpinned Python dependency',Severity.MEDIUM,
                        f'Dependency is not pinned: {s}', 'requirements.txt', i, s,
                        'Pin production dependencies to reviewed versions and use automated update tooling.',
                        'supply-chain','CWE-1104','LLM05','A.8.8'))
        pkg = root / 'package.json'
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text())
                for section in ('dependencies','devDependencies'):
                    for name, version in data.get(section,{}).items():
                        if str(version).startswith(('*','latest','http:')):
                            out.append(Finding('AS-SC-002','Risky JavaScript dependency constraint',Severity.MEDIUM,
                                f'{name} uses an unsafe version constraint: {version}', 'package.json', 1,
                                f'{name}: {version}', 'Pin dependencies and commit a lockfile.',
                                'supply-chain','CWE-1104','LLM05','A.8.8'))
            except Exception:
                pass
        return out
