from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _risk_rank(risk: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(risk).upper(), 0)


def load_reports(paths: list[str]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for path in paths:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or "summary" not in payload:
            raise ValueError(f"Not an AgentShield JSON report: {path}")
        payload["_source"] = path
        reports.append(payload)
    return reports


def build_dashboard_data(reports: list[dict[str, Any]]) -> dict[str, Any]:
    provider_rows: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []
    scores: list[int] = []
    for report in reports:
        summary = report.get("summary", {})
        meta = report.get("metadata", {})
        provider = meta.get("provider") or summary.get("provider") or "repository"
        score = int(summary.get("score", 0))
        scores.append(score)
        provider_rows.append({
            "provider": provider,
            "score": score,
            "risk_level": summary.get("risk_level", "UNKNOWN"),
            "findings": int(summary.get("findings", 0)),
            "severity": summary.get("severity", {}),
            "source": report.get("_source", ""),
        })
        for f in report.get("findings", []):
            item = dict(f)
            item["provider"] = provider
            all_findings.append(item)
        for x in meta.get("role_assessments", []):
            identities.append({
                "provider": provider,
                "name": x.get("name"),
                "type": "IAM Role",
                "blast_radius": x.get("blast_radius", "LOW"),
                "risk_points": x.get("risk_points", 0),
                "ai": bool(x.get("candidate_ai_role")),
                "roles": x.get("attached_policies", []),
            })
        for x in meta.get("identity_assessments", []):
            identities.append({
                "provider": provider,
                "name": x.get("name"),
                "type": x.get("principal_type") or x.get("member_type") or "Identity",
                "blast_radius": x.get("blast_radius", "LOW"),
                "risk_points": x.get("risk_points", 0),
                "ai": bool(x.get("candidate_ai_identity")),
                "roles": x.get("roles", []),
            })

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    all_findings.sort(key=lambda f: (-sev_rank.get(str(f.get("severity", "INFO")).upper(), 0), str(f.get("provider")), str(f.get("rule_id"))))
    identities.sort(key=lambda x: (-_risk_rank(x["blast_radius"]), -int(x.get("risk_points", 0)), str(x.get("name", ""))))
    provider_rows.sort(key=lambda x: (-_risk_rank(str(x["risk_level"])), x["score"]))
    overall_score = round(sum(scores) / len(scores)) if scores else 0
    overall_risk = "LOW"
    if any(_risk_rank(str(x["risk_level"])) >= 4 for x in provider_rows) or overall_score < 40:
        overall_risk = "CRITICAL"
    elif any(_risk_rank(str(x["risk_level"])) >= 3 for x in provider_rows) or overall_score < 65:
        overall_risk = "HIGH"
    elif any(_risk_rank(str(x["risk_level"])) >= 2 for x in provider_rows) or overall_score < 85:
        overall_risk = "MEDIUM"
    return {
        "overall_score": overall_score,
        "overall_risk": overall_risk,
        "providers": provider_rows,
        "findings": all_findings,
        "identities": identities,
        "reports": len(reports),
    }


def write_dashboard_json(data: dict[str, Any], path: str) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_dashboard_html(data: dict[str, Any], path: str) -> None:
    provider_rows = "".join(
        f'''<tr><td><b>{_esc(x['provider']).upper()}</b></td><td class="scorecell">{x['score']}/100</td><td><span class="sev {_esc(str(x['risk_level']).lower())}">{_esc(x['risk_level'])}</span></td><td>{x['findings']}</td><td>{_esc(x.get('severity',{}).get('CRITICAL',0))}</td><td>{_esc(x.get('severity',{}).get('HIGH',0))}</td></tr>'''
        for x in data["providers"]
    )
    identity_rows = "".join(
        f'''<tr><td>{_esc(x['provider']).upper()}</td><td><b>{_esc(x['name'])}</b><br><small>{_esc(x['type'])}</small></td><td>{'Yes' if x['ai'] else 'No'}</td><td><span class="sev {_esc(str(x['blast_radius']).lower())}">{_esc(x['blast_radius'])}</span></td><td>{_esc(x['risk_points'])}</td><td>{_esc(', '.join(x.get('roles',[])[:4]) or '-')}</td></tr>'''
        for x in data["identities"][:30]
    ) or '<tr><td colspan="6" class="muted">No cloud identity assessments in supplied reports.</td></tr>'
    finding_rows = "".join(
        f'''<tr><td>{_esc(f.get('provider','')).upper()}</td><td><span class="sev {_esc(str(f.get('severity','INFO')).lower())}">{_esc(f.get('severity','INFO'))}</span></td><td><code>{_esc(f.get('rule_id',''))}</code></td><td><b>{_esc(f.get('title',''))}</b><br><small>{_esc(f.get('message',''))}</small></td><td><code>{_esc(f.get('file',''))}</code></td></tr>'''
        for f in data["findings"][:80]
    ) or '<tr><td colspan="5" class="muted">No findings detected.</td></tr>'

    doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield Multi-Cloud Dashboard</title>
<style>
:root{{--bg:#07101f;--card:#0d1930;--line:#22365a;--text:#eef5ff;--muted:#9fb0cc;--accent:#68e1fd}}*{{box-sizing:border-box}}body{{font-family:Inter,ui-sans-serif,system-ui,Arial,sans-serif;max-width:1500px;margin:0 auto;padding:42px 24px;background:linear-gradient(150deg,#07101f,#0a1325 55%,#08172a);color:var(--text)}}.brand{{letter-spacing:.08em;text-transform:uppercase;color:var(--accent);font-weight:800}}.card{{background:rgba(13,25,48,.94);border:1px solid var(--line);border-radius:18px;padding:26px;margin-bottom:20px;box-shadow:0 18px 50px rgba(0,0,0,.18)}}h1{{font-size:36px;margin:5px 0 8px}}h2{{margin-top:0}}.hero{{display:flex;gap:32px;align-items:end;flex-wrap:wrap}}.score{{font-size:70px;font-weight:850;letter-spacing:-.05em}}.muted,small{{color:var(--muted)}}.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:850px}}th,td{{text-align:left;padding:13px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:#b9c9e6;font-size:12px;text-transform:uppercase;letter-spacing:.05em}}code{{color:#b7f4ff}}.scorecell{{font-size:20px;font-weight:800}}.sev{{display:inline-block;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:800;letter-spacing:.04em}}.critical{{background:#5f1222;color:#ffd4dc}}.high{{background:#5a2a12;color:#ffdfc7}}.medium{{background:#55450d;color:#fff0ad}}.low{{background:#123d37;color:#c8fff5}}.info{{background:#25344c;color:#dbe7ff}}
</style></head><body>
<div class="brand">AgentShield</div>
<div class="card"><h1>Multi-Cloud AI Security Dashboard</h1><div class="hero"><div><div class="score">{data['overall_score']}/100</div><div>Overall posture score</div></div><div><div class="sev {_esc(data['overall_risk'].lower())}">{_esc(data['overall_risk'])}</div><p class="muted">Aggregated from {data['reports']} AgentShield reports • {len(data['findings'])} findings • {len(data['identities'])} ranked identities/roles</p></div></div></div>
<div class="card"><h2>Provider Posture</h2><div class="scroll"><table><thead><tr><th>Provider</th><th>Score</th><th>Risk</th><th>Findings</th><th>Critical</th><th>High</th></tr></thead><tbody>{provider_rows}</tbody></table></div></div>
<div class="card"><h2>Highest Blast-Radius Identities</h2><p class="muted">Ranks AWS roles, Azure/Entra principals and GCP IAM identities in a common view.</p><div class="scroll"><table><thead><tr><th>Provider</th><th>Identity</th><th>AI</th><th>Blast radius</th><th>Risk points</th><th>Roles / Policies</th></tr></thead><tbody>{identity_rows}</tbody></table></div></div>
<div class="card"><h2>Top Security Findings</h2><div class="scroll"><table><thead><tr><th>Provider</th><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th></tr></thead><tbody>{finding_rows}</tbody></table></div></div>
</body></html>'''
    Path(path).write_text(doc, encoding="utf-8")
