from __future__ import annotations
import argparse
import sys
from .scanner import AgentShieldScanner
from .reporters import write_json, write_html, write_sarif
from .baseline import write_baseline, compare_baseline_file, format_diff
from .graph import write_mermaid


def _add_outputs(p: argparse.ArgumentParser) -> None:
    p.add_argument('--json', dest='json_path', help='Write JSON report')
    p.add_argument('--html', dest='html_path', help='Write HTML report')
    p.add_argument('--sarif', dest='sarif_path', help='Write SARIF 2.1.0 report')
    p.add_argument('--fail-on', choices=['critical','high','medium','low'], default=None,
                   help='Exit 2 when a finding at or above this severity exists')
    p.add_argument('--baseline-out', help='Save this assessment as a JSON baseline')
    p.add_argument('--compare-with', help='Compare this assessment with a previous AgentShield JSON/baseline')
    p.add_argument('--graph', dest='graph_path', help='Write a Mermaid blast-radius/attack-path graph (.mmd)')
    p.add_argument('--min-score', type=int, default=None, help='Exit 2 if security score is below this value (0-100)')
    p.add_argument('--fail-on-new', action='store_true', help='With --compare-with, exit 3 when new findings are introduced')


def _emit(result, args, resource_word: str = 'files') -> int:
    s = result.summary()
    print(f"AgentShield | score {s['score']}/100 | risk {s['risk_level']} | {resource_word} {s['files_scanned']} | findings {s['findings']}")
    provider = result.metadata.get('provider')
    if provider == 'aws':
        print(f"AWS account {result.metadata.get('account_id')} | region {result.metadata.get('region')} | principal {result.metadata.get('principal_arn')}")
        roles = result.metadata.get('role_assessments', [])
        for role in roles[:10]:
            marker = 'AI' if role.get('candidate_ai_role') else '--'
            print(f"[ROLE {role.get('blast_radius', 'LOW'):8}] {marker:2} {role.get('name')} | risk-points {role.get('risk_points')} | findings {role.get('finding_count')}")
    elif provider == 'azure':
        subs = result.metadata.get('subscriptions', [])
        tenants = ','.join(result.metadata.get('tenant_ids', [])) or 'unknown'
        print(f"Azure tenants {tenants} | subscriptions {len(subs)} | AI resources {result.metadata.get('ai_resources_scanned', 0)}")
        for ident in result.metadata.get('identity_assessments', [])[:10]:
            marker = 'AI' if ident.get('candidate_ai_identity') else '--'
            print(f"[IDENTITY {ident.get('blast_radius', 'LOW'):8}] {marker:2} {ident.get('name')} | {ident.get('principal_type')} | risk-points {ident.get('risk_points')} | findings {ident.get('finding_count')}")
    elif provider == 'gcp':
        projects = result.metadata.get('projects', [])
        print(f"GCP projects {len(projects)} | service accounts {result.metadata.get('service_accounts_scanned', 0)}")
        for ident in result.metadata.get('identity_assessments', [])[:10]:
            marker = 'AI' if ident.get('candidate_ai_identity') else '--'
            print(f"[IDENTITY {ident.get('blast_radius', 'LOW'):8}] {marker:2} {ident.get('name')} | {ident.get('member_type')} | risk-points {ident.get('risk_points')} | findings {ident.get('finding_count')}")
    for f in result.findings:
        print(f"[{f.severity.value:8}] {f.rule_id} {f.file}:{f.line} - {f.title}")
    if args.json_path: write_json(result, args.json_path)
    if args.html_path: write_html(result, args.html_path)
    if args.sarif_path: write_sarif(result, args.sarif_path)
    if getattr(args, 'graph_path', None): write_mermaid(result, args.graph_path)
    if getattr(args, 'baseline_out', None): write_baseline(result, args.baseline_out)
    diff = None
    if getattr(args, 'compare_with', None):
        diff = compare_baseline_file(args.compare_with, result)
        print(format_diff(diff))
    if getattr(args, 'min_score', None) is not None:
        if not 0 <= args.min_score <= 100:
            raise ValueError('--min-score must be between 0 and 100')
        if result.score < args.min_score: return 2
    if args.fail_on:
        rank={'critical':4,'high':3,'medium':2,'low':1}; sev={'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0}
        if any(sev[f.severity.value] >= rank[args.fail_on] for f in result.findings): return 2
    if getattr(args, 'fail_on_new', False) and diff and diff['new_findings']:
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backward compatibility: `agentshield .` is treated as `agentshield scan .`.
    if not argv or argv[0] not in {'scan', 'aws', 'azure', 'gcp', 'dashboard', '-h', '--help'}:
        argv.insert(0, 'scan')

    p = argparse.ArgumentParser(prog='agentshield', description='Security posture scanner for AI-agent projects and cloud identities')
    sub = p.add_subparsers(dest='command', required=True)

    local = sub.add_parser('scan', help='Scan a local AI-agent repository')
    local.add_argument('path', nargs='?', default='.')
    _add_outputs(local)

    aws = sub.add_parser('aws', help='Read-only AWS IAM and cloud security assessment')
    aws.add_argument('--profile', default=None, help='AWS shared-credentials profile name')
    aws.add_argument('--region', default=None, help='AWS region for regional controls')
    aws.add_argument('--role-pattern', default=None, help='Only scan IAM roles matching this glob, e.g. "*Agent*"')
    aws.add_argument('--ai-only', action='store_true', help='Assess only roles that look like AI/agent workload identities')
    aws.add_argument('--max-roles', type=int, default=250, help='Maximum IAM roles to assess (default: 250)')
    _add_outputs(aws)

    azure = sub.add_parser('azure', help='Read-only Azure RBAC, Entra identity and AI-resource assessment')
    azure.add_argument('--credential', choices=['default', 'cli'], default='default',
                       help='Credential mode: DefaultAzureCredential or Azure CLI only (default: default)')
    azure.add_argument('--tenant-id', default=None, help='Optional Entra tenant ID')
    azure.add_argument('--subscription', action='append', dest='subscriptions', default=None,
                       help='Restrict to a subscription ID; repeat for multiple subscriptions')
    azure.add_argument('--principal-pattern', default=None,
                       help='Only assess principals matching this glob, e.g. "*Agent*"')
    azure.add_argument('--ai-only', action='store_true', help='Assess only likely AI/agent workload identities')
    azure.add_argument('--max-assignments', type=int, default=1000,
                       help='Maximum RBAC assignments per subscription (default: 1000)')
    _add_outputs(azure)

    gcp = sub.add_parser('gcp', help='Read-only GCP IAM, service-account and AI-workload assessment')
    gcp.add_argument('--project', action='append', dest='projects', default=None,
                     help='Restrict to a GCP project ID; repeat for multiple projects')
    gcp.add_argument('--principal-pattern', default=None,
                     help='Only assess principals matching this glob, e.g. "*agent*"')
    gcp.add_argument('--ai-only', action='store_true', help='Assess only likely AI/agent workload identities')
    gcp.add_argument('--max-projects', type=int, default=100, help='Maximum projects to assess (default: 100)')
    gcp.add_argument('--max-service-accounts', type=int, default=500,
                     help='Maximum service accounts per project to inspect (default: 500)')
    gcp.add_argument('--quota-project-id', default=None,
                     help='Optional quota/billing project for Application Default Credentials')
    _add_outputs(gcp)

    dashboard = sub.add_parser('dashboard', help='Build a unified dashboard from AgentShield JSON reports')
    dashboard.add_argument('reports', nargs='+', help='AgentShield JSON reports to aggregate')
    dashboard.add_argument('--html', dest='html_path', required=True, help='Write standalone multi-cloud dashboard HTML')
    dashboard.add_argument('--json', dest='json_path', default=None, help='Optionally write aggregated dashboard JSON')

    a = p.parse_args(argv)
    if a.command == 'dashboard':
        from .dashboard import load_reports, build_dashboard_data, write_dashboard_html, write_dashboard_json
        data = build_dashboard_data(load_reports(a.reports))
        write_dashboard_html(data, a.html_path)
        if a.json_path:
            write_dashboard_json(data, a.json_path)
        print(f"AgentShield dashboard | score {data['overall_score']}/100 | risk {data['overall_risk']} | reports {data['reports']} | findings {len(data['findings'])}")
        return 0
    if a.command == 'scan':
        return _emit(AgentShieldScanner().scan(a.path), a, 'files')

    if a.command == 'aws':
        from .scanners.aws import AwsSecurityScanner
        result = AwsSecurityScanner(
            profile=a.profile, region=a.region, role_pattern=a.role_pattern,
            ai_only=a.ai_only, max_roles=a.max_roles,
        ).scan()
        return _emit(result, a, 'roles')

    if a.command == 'azure':
        from .scanners.azure import AzureSecurityScanner
        result = AzureSecurityScanner(
            credential_mode=a.credential,
            tenant_id=a.tenant_id,
            subscriptions=a.subscriptions,
            principal_pattern=a.principal_pattern,
            ai_only=a.ai_only,
            max_assignments=a.max_assignments,
        ).scan()
        return _emit(result, a, 'assignments')

    from .scanners.gcp import GcpSecurityScanner
    result = GcpSecurityScanner(
        projects=a.projects,
        principal_pattern=a.principal_pattern,
        ai_only=a.ai_only,
        max_projects=a.max_projects,
        max_service_accounts=a.max_service_accounts,
        quota_project_id=a.quota_project_id,
    ).scan()
    return _emit(result, a, 'IAM memberships')


if __name__ == '__main__':
    raise SystemExit(main())
