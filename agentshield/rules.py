from __future__ import annotations
from dataclasses import dataclass
import re
from .models import Severity

@dataclass(frozen=True)
class RegexRule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    remediation: str
    category: str
    cwe: str | None = None
    owasp_llm: str | None = None
    iso27001: str | None = None

RULES = [
    RegexRule('AS-SEC-001','AWS access key committed',Severity.CRITICAL,re.compile(r'AKIA[0-9A-Z]{16}'),
              'Possible AWS access key found in source.', 'Revoke the key immediately, remove it from history, and use a secrets manager.',
              'secrets','CWE-798','LLM02','A.8.24'),
    RegexRule('AS-SEC-002','OpenAI-style API key committed',Severity.CRITICAL,re.compile(r'\bsk-[A-Za-z0-9_-]{20,}\b'),
              'Possible API key found in source.', 'Rotate the key and load it at runtime from a secret store or environment variable.',
              'secrets','CWE-798','LLM02','A.8.24'),
    RegexRule('AS-SEC-003','Private key committed',Severity.CRITICAL,re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
              'Private key material appears to be committed.', 'Remove and rotate the private key. Store keys in a managed secret/key vault.',
              'secrets','CWE-321','LLM02','A.8.24'),
    RegexRule('AS-AGT-001','Unrestricted shell execution',Severity.HIGH,re.compile(r'\b(?:os\.system|subprocess\.(?:run|Popen|call)|child_process\.exec|execSync)\s*\('),
              'Agent code can execute operating-system commands.', 'Isolate command execution, use strict allowlists, and require approval for dangerous actions.',
              'agent-capability','CWE-78','LLM06','A.8.18'),
    RegexRule('AS-AGT-002','Dynamic code execution',Severity.CRITICAL,re.compile(r'\b(?:eval|exec)\s*\('),
              'Dynamic code execution was detected.', 'Avoid eval/exec on model or user-controlled content. Replace with explicit parsers and allowlisted actions.',
              'agent-capability','CWE-95','LLM06','A.8.28'),
    RegexRule('AS-IAM-001','Wildcard permission',Severity.HIGH,re.compile(r'(?i)(?:action|permissions?|scope)["\'\s:=\[,-]+\*'),
              'Wildcard permission may grant the agent excessive privileges.', 'Replace wildcard access with the minimum required actions/resources.',
              'iam','CWE-250','LLM06','A.5.15'),
    RegexRule('AS-IAM-002','Administrator privilege',Severity.CRITICAL,re.compile(r'(?i)AdministratorAccess|Owner\b|roles?/owner|admin(?:istrator)?[_ -]?role'),
              'Administrator-level privilege reference detected.', 'Create a dedicated least-privilege role for the agent and separate read/write capabilities.',
              'iam','CWE-250','LLM06','A.5.18'),
    RegexRule('AS-NET-001','Unrestricted network binding',Severity.MEDIUM,re.compile(r'(?i)(?:0\.0\.0\.0|host\s*=\s*["\']0\.0\.0\.0["\'])'),
              'Service may be exposed on all network interfaces.', 'Bind to localhost/private interface unless public exposure is explicitly required and protected.',
              'network','CWE-284',None,'A.8.20'),
    RegexRule('AS-AUD-001','Logging explicitly disabled',Severity.HIGH,re.compile(r'(?i)(?:audit|logging|telemetry)[_-]?(?:enabled)?\s*[=:]\s*(?:false|0|off)'),
              'Audit/logging appears to be disabled.', 'Enable immutable audit logs for agent actions, tool calls, identity, inputs, and outcomes.',
              'audit',None,'LLM09','A.8.15'),
    RegexRule('AS-HITL-001','Human approval disabled',Severity.HIGH,re.compile(r'(?i)(?:human[_ -]?(?:approval|review)|require[_ -]?approval|hitl)\s*[=:]\s*(?:false|0|off)'),
              'Human approval control appears to be disabled.', 'Require approval for high-impact actions such as payments, deletion, external messaging, and privilege changes.',
              'governance',None,'LLM06','A.5.3'),
]
