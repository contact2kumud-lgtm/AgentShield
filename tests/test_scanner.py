from pathlib import Path
from agentshield.scanner import AgentShieldScanner
from agentshield.reporters import write_json, write_html, write_sarif


def test_detects_risky_agent():
    root = Path(__file__).parents[1] / "examples"
    result = AgentShieldScanner().scan(root)
    ids = {f.rule_id for f in result.findings}
    assert "AS-IAM-002" in ids
    assert "AS-AGT-001" in ids
    assert "AS-AUD-001" in ids
    assert "AS-HITL-001" in ids
    assert result.score < 70


def test_report_outputs(tmp_path):
    root = Path(__file__).parents[1] / "examples"
    result = AgentShieldScanner().scan(root)
    j = tmp_path / "r.json"
    h = tmp_path / "r.html"
    s = tmp_path / "r.sarif"
    write_json(result, str(j)); write_html(result, str(h)); write_sarif(result, str(s))
    assert j.exists() and h.exists() and s.exists()
