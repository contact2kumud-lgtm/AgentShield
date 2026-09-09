from __future__ import annotations
from pathlib import Path
import re
from ..models import Finding, Severity

class GitHubActionsScanner:
    def scan(self, root: Path) -> list[Finding]:
        out=[]
        wf = root / '.github' / 'workflows'
        if not wf.exists(): return out
        for p in list(wf.glob('*.yml')) + list(wf.glob('*.yaml')):
            text=p.read_text(errors='ignore')
            rel=str(p.relative_to(root))
            for i,line in enumerate(text.splitlines(),1):
                if re.search(r'permissions\s*:\s*write-all',line,re.I):
                    out.append(Finding('AS-CI-001','GitHub Actions write-all permission',Severity.HIGH,
                        'Workflow grants write-all token permissions.',rel,i,line.strip(),
                        'Set explicit least-privilege GITHUB_TOKEN permissions per workflow/job.',
                        'ci-cd','CWE-250',None,'A.8.4'))
                if 'pull_request_target:' in line:
                    out.append(Finding('AS-CI-002','pull_request_target workflow detected',Severity.MEDIUM,
                        'pull_request_target can expose privileged tokens when untrusted PR code is checked out.',rel,i,line.strip(),
                        'Avoid checking out untrusted PR code in privileged pull_request_target workflows.',
                        'ci-cd','CWE-829',None,'A.8.28'))
        return out
