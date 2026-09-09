from __future__ import annotations
from pathlib import Path
from ..models import Finding
from ..rules import RULES

TEXT_EXTENSIONS = {'.py','.js','.ts','.tsx','.jsx','.json','.yaml','.yml','.toml','.ini','.cfg','.conf','.env','.md','.txt','.sh','.ps1'}
SKIP_DIRS = {'.git','.venv','venv','node_modules','dist','build','.pytest_cache','__pycache__'}
MAX_FILE_SIZE = 2_000_000


def _ignore_patterns(root: Path) -> list[str]:
    f = root / '.agentshieldignore'
    if not f.exists():
        return []
    return [x.strip() for x in f.read_text(errors='ignore').splitlines() if x.strip() and not x.lstrip().startswith('#')]


def _ignored(rel: Path, patterns: list[str]) -> bool:
    s = rel.as_posix()
    for pat in patterns:
        p = pat.rstrip('/')
        if s == p or s.startswith(p + '/') or rel.match(pat):
            return True
    return False


class SourceScanner:
    def scan(self, root: Path) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        count = 0
        patterns = _ignore_patterns(root)
        for p in root.rglob('*'):
            if not p.is_file() or any(part in SKIP_DIRS for part in p.parts):
                continue
            rel = p.relative_to(root)
            if _ignored(rel, patterns):
                continue
            if p.suffix.lower() not in TEXT_EXTENSIONS and p.name not in {'.env','Dockerfile','requirements.txt'}:
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
                text = p.read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            count += 1
            lines = text.splitlines() or ['']
            for rule in RULES:
                for lineno, line in enumerate(lines, 1):
                    m = rule.pattern.search(line)
                    if not m:
                        continue
                    evidence = line.strip()[:180]
                    findings.append(Finding(rule.id, rule.title, rule.severity, rule.message,
                                            str(rel), lineno, evidence, rule.remediation,
                                            rule.category, rule.cwe, rule.owasp_llm, rule.iso27001))
        return findings, count
