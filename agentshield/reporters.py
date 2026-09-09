from __future__ import annotations
import html, json
from pathlib import Path
from .models import ScanResult


def write_json(result: ScanResult, path: str) -> None:
    Path(path).write_text(json.dumps({
        'summary': result.summary(),
        'metadata': result.metadata,
        'findings': [f.to_dict() for f in result.findings]
    }, indent=2), encoding='utf-8')


def write_sarif(result: ScanResult, path: str) -> None:
    rules={}
    results=[]
    level={'CRITICAL':'error','HIGH':'error','MEDIUM':'warning','LOW':'note','INFO':'none'}
    for f in result.findings:
        rules[f.rule_id]={'id':f.rule_id,'name':f.title,'shortDescription':{'text':f.title},'help':{'text':f.remediation}}
        results.append({'ruleId':f.rule_id,'level':level[f.severity.value], 'message':{'text':f.message},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':f.file},'region':{'startLine':max(1, f.line)}}}]})
    sarif={'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'AgentShield','rules':list(rules.values())}},'results':results}]}
    Path(path).write_text(json.dumps(sarif, indent=2), encoding='utf-8')


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ''))


def write_html(result: ScanResult, path: str) -> None:
    rows=''.join(f'''<tr><td><span class="sev {_esc(f.severity.value.lower())}">{_esc(f.severity.value)}</span></td><td><code>{_esc(f.rule_id)}</code></td><td><b>{_esc(f.title)}</b><br><small>{_esc(f.message)}</small></td><td><code>{_esc(f.file)}</code></td><td>{_esc(f.remediation)}</td></tr>''' for f in result.findings)
    s=result.summary()
    meta=result.metadata
    provider = ''
    blast_section = ''
    gaps_section = ''
    provider_name = str(meta.get('provider', '')).upper() or 'Repository'

    if meta.get('provider') == 'aws':
        provider = f'''<div class="grid"><div class="mini"><span>Provider</span><b>AWS</b></div><div class="mini"><span>Account</span><b>{_esc(meta.get('account_id',''))}</b></div><div class="mini"><span>Region</span><b>{_esc(meta.get('region',''))}</b></div><div class="mini wide"><span>Scanner principal</span><b>{_esc(meta.get('principal_arn',''))}</b></div></div>'''
        role_rows = ''.join(f'''<tr><td><b>{_esc(r.get('name',''))}</b></td><td>{'Yes' if r.get('candidate_ai_role') else 'No'}</td><td><span class="sev {_esc(str(r.get('blast_radius','LOW')).lower())}">{_esc(r.get('blast_radius','LOW'))}</span></td><td>{_esc(r.get('risk_points',0))}</td><td>{_esc(', '.join(r.get('trusted_services',[])[:4]) or '-')}</td><td>{_esc('; '.join(r.get('reasons',[])[:4]) or '-')}</td></tr>''' for r in meta.get('role_assessments', []))
        blast_section = f'''<div class="card"><h2>AWS IAM Blast-Radius Analysis</h2><p class="muted">Roles are ranked by privilege, trust exposure and sensitive/destructive capabilities. “AI role” is a heuristic based on role naming and trusted AWS workload services.</p><div class="scroll"><table><thead><tr><th>Role</th><th>AI role</th><th>Blast radius</th><th>Risk points</th><th>Trusted services</th><th>Key reasons</th></tr></thead><tbody>{role_rows}</tbody></table></div></div>'''

    elif meta.get('provider') == 'azure':
        subs = meta.get('subscriptions', [])
        sub_names = ', '.join((x.get('name') or x.get('id') or '') for x in subs[:4])
        if len(subs) > 4:
            sub_names += f' +{len(subs)-4} more'
        provider = f'''<div class="grid"><div class="mini"><span>Provider</span><b>Microsoft Azure</b></div><div class="mini"><span>Tenant(s)</span><b>{_esc(', '.join(meta.get('tenant_ids', [])) or 'Unknown')}</b></div><div class="mini"><span>Subscriptions</span><b>{len(subs)}</b></div><div class="mini wide"><span>Scope</span><b>{_esc(sub_names or 'Accessible subscriptions')}</b></div></div>'''
        identity_rows = ''.join(f'''<tr><td><b>{_esc(i.get('name',''))}</b><br><small>{_esc(i.get('principal_type',''))}</small></td><td>{'Yes' if i.get('candidate_ai_identity') else 'No'}</td><td><span class="sev {_esc(str(i.get('blast_radius','LOW')).lower())}">{_esc(i.get('blast_radius','LOW'))}</span></td><td>{_esc(i.get('risk_points',0))}</td><td>{_esc(', '.join(i.get('roles',[])[:4]) or '-')}</td><td>{_esc('; '.join(i.get('reasons',[])[:4]) or '-')}</td></tr>''' for i in meta.get('identity_assessments', []))
        blast_section = f'''<div class="card"><h2>Azure Identity Blast-Radius Analysis</h2><p class="muted">Entra principals are ranked using Azure RBAC privilege, assignment scope, sensitive key/secret access and AI-workload heuristics.</p><div class="scroll"><table><thead><tr><th>Identity</th><th>AI identity</th><th>Blast radius</th><th>Risk points</th><th>Roles</th><th>Key reasons</th></tr></thead><tbody>{identity_rows}</tbody></table></div></div>'''

    elif meta.get('provider') == 'gcp':
        projects = meta.get('projects', [])
        project_names = ', '.join((x.get('display_name') or x.get('project_id') or '') for x in projects[:4])
        if len(projects) > 4:
            project_names += f' +{len(projects)-4} more'
        provider = f'''<div class="grid"><div class="mini"><span>Provider</span><b>Google Cloud</b></div><div class="mini"><span>Projects</span><b>{len(projects)}</b></div><div class="mini"><span>Service Accounts</span><b>{_esc(meta.get('service_accounts_scanned', 0))}</b></div><div class="mini wide"><span>Scope</span><b>{_esc(project_names or 'Accessible projects')}</b></div></div>'''
        identity_rows = ''.join(f'''<tr><td><b>{_esc(i.get('name',''))}</b><br><small>{_esc(i.get('member_type',''))}</small></td><td>{'Yes' if i.get('candidate_ai_identity') else 'No'}</td><td><span class="sev {_esc(str(i.get('blast_radius','LOW')).lower())}">{_esc(i.get('blast_radius','LOW'))}</span></td><td>{_esc(i.get('risk_points',0))}</td><td>{_esc(', '.join(i.get('roles',[])[:4]) or '-')}</td><td>{_esc('; '.join(i.get('reasons',[])[:4]) or '-')}</td></tr>''' for i in meta.get('identity_assessments', []))
        blast_section = f'''<div class="card"><h2>GCP Identity Blast-Radius Analysis</h2><p class="muted">IAM principals are ranked using project-wide privilege, service-account impersonation/key risk, sensitive-data roles and AI-workload heuristics.</p><div class="scroll"><table><thead><tr><th>Identity</th><th>AI identity</th><th>Blast radius</th><th>Risk points</th><th>Roles</th><th>Key reasons</th></tr></thead><tbody>{identity_rows}</tbody></table></div></div>'''

    gaps = meta.get('visibility_gaps', [])
    if gaps:
        gaps_section = '<div class="card"><h2>Visibility Gaps</h2><p class="muted">These controls could not be fully evaluated with the current read-only identity.</p><ul>' + ''.join(f'<li>{_esc(g)}</li>' for g in gaps) + '</ul></div>'

    empty = '<tr><td colspan="5" class="muted">No findings detected.</td></tr>' if not rows else ''
    doc=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield Report</title>
<style>
:root{{--bg:#07101f;--card:#0d1930;--line:#22365a;--text:#eef5ff;--muted:#9fb0cc;--accent:#68e1fd}}*{{box-sizing:border-box}}body{{font-family:Inter,ui-sans-serif,system-ui,Arial,sans-serif;max-width:1400px;margin:0 auto;padding:42px 24px;background:linear-gradient(160deg,#07101f,#0a1325 55%,#08172a);color:var(--text)}}.brand{{letter-spacing:.08em;text-transform:uppercase;color:var(--accent);font-weight:800}}.card{{background:rgba(13,25,48,.92);border:1px solid var(--line);border-radius:18px;padding:26px;margin-bottom:20px;box-shadow:0 18px 50px rgba(0,0,0,.18)}}h1{{font-size:34px;margin:5px 0 8px}}h2{{margin-top:0}}.score{{font-size:62px;font-weight:850;letter-spacing:-.04em}}.muted,small{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:20px}}.mini{{background:#0a1428;border:1px solid var(--line);border-radius:12px;padding:14px}}.mini span{{display:block;color:var(--muted);font-size:12px;margin-bottom:5px;text-transform:uppercase;letter-spacing:.06em}}.mini b{{font-size:14px;overflow-wrap:anywhere}}.wide{{grid-column:span 1}}.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:900px}}th,td{{text-align:left;padding:13px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:#b9c9e6;font-size:12px;text-transform:uppercase;letter-spacing:.05em}}code{{color:#b7f4ff}}.sev{{display:inline-block;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:800;letter-spacing:.04em}}.critical{{background:#5f1222;color:#ffd4dc}}.high{{background:#5a2a12;color:#ffdfc7}}.medium{{background:#55450d;color:#fff0ad}}.low{{background:#123d37;color:#c8fff5}}@media(max-width:850px){{.grid{{grid-template-columns:1fr 1fr}}.wide{{grid-column:span 2}}}}
</style></head><body>
<div class="brand">AgentShield</div><div class="card"><h1>AI & Cloud Security Posture Report</h1><div class="score">{s['score']}/100</div><p>Risk: <b>{s['risk_level']}</b> &nbsp;•&nbsp; Provider: <b>{_esc(provider_name)}</b> &nbsp;•&nbsp; Scanned: {s['files_scanned']} &nbsp;•&nbsp; Findings: {s['findings']}</p>{provider}</div>
{blast_section}
<div class="card"><h2>Security Findings</h2><div class="scroll"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead><tbody>{rows}{empty}</tbody></table></div></div>
{gaps_section}
</body></html>'''
    Path(path).write_text(doc, encoding='utf-8')
