"""Offline coverage mapping against a frozen ground-truth file.

This module is evaluation-only: it is never imported by the investigation engine
and only runs when an operator explicitly asks for a coverage report. The truth
file contains root-cause mappings, not challenge answers or hints.
"""
import collections

BEHAVIOR_ROOTS = {
    'authentication_bypass': ['RC-SQLI-LOGIN'],
    'default_credentials': ['RC-WEAK-PASSWORD'],
    'anonymous_configuration': ['RC-CONFIG-EXPOSURE'],
    'anonymous_metrics': ['RC-METRICS'],
    'log_directory_exposed': ['RC-ACCESS-LOG'],
    'static_directory_listing': ['RC-STATIC-FILE-EXPOSURE'],
    'anonymous_file_download': ['RC-STATIC-FILE-EXPOSURE'],
    'anonymous_directory_listing': ['RC-STATIC-FILE-EXPOSURE'],
    'debug_stack_disclosure': ['RC-ERROR-DISCLOSURE'],
    'script_execution': ['RC-DOM-XSS'],
    'cross_account_read': ['RC-IDOR-BASKET'],
}
KIND_ROOTS = {
    'sql_login': ['RC-SQLI-LOGIN'],
    'weak_password': ['RC-WEAK-PASSWORD'],
}
PATH_ROOTS = {
    '/metrics': ['RC-METRICS'],
    '/support/logs': ['RC-ACCESS-LOG'],
    '/ftp/': ['RC-STATIC-FILE-EXPOSURE'],
}


def roots_for(observation):
    """Juice Shop evaluation only: exact surface + method + signal must agree."""
    from urllib.parse import urlsplit,parse_qs
    u=urlsplit(observation.get('url',''));path=u.path.rstrip('/') or '/'
    kind=observation.get('kind');behavior=observation.get('behavior')
    method=observation.get('method','GET')
    if kind in {'sql_error','sql_boolean'} and method=='GET' and path=='/rest/products/search' and observation.get('parameter')=='q':
        return ['RC-SQLI-SEARCH']
    if kind=='sql_login' and method=='POST' and path=='/rest/user/login' and behavior=='authentication_bypass': return ['RC-SQLI-LOGIN']
    if kind=='weak_password' and method=='POST' and path=='/rest/user/login' and behavior=='default_credentials': return ['RC-WEAK-PASSWORD']
    if kind=='auth_idor' and path.startswith('/rest/basket/') and behavior=='cross_account_read': return ['RC-IDOR-BASKET']
    if kind=='browser_xss' and u.fragment.startswith('/search?') and behavior=='script_execution': return ['RC-DOM-XSS']
    if method!='GET': return []
    rules={
        '/metrics':('anonymous_metrics','RC-METRICS'),
        '/support/logs':('log_directory_exposed','RC-ACCESS-LOG'),
        '/rest/admin/application-configuration':('anonymous_configuration','RC-CONFIG-EXPOSURE'),
    }
    if path in rules and behavior==rules[path][0]: return [rules[path][1]]
    if (path=='/ftp' or path.startswith('/ftp/')) and behavior in {'anonymous_file_download','anonymous_directory_listing','static_directory_listing'}:
        return ['RC-STATIC-FILE-EXPOSURE']
    return []


def covered_roots(result, *, confirmed_only=False):
    """Return candidate surfaces and observed behaviors, never reviewed vulnerabilities."""
    if confirmed_only: return set(),set()
    covered, confirmed = set(), set()
    for observation in result.get('observations', []):
        verdict = observation.get('verdict')
        if verdict not in {'candidate', 'verified_behavior'}:
            continue
        if confirmed_only and verdict != 'verified_behavior':
            continue
        roots = roots_for(observation)
        if not roots:
            continue
        covered.update(roots)
        if verdict == 'verified_behavior':
            confirmed.update(roots)
    return covered, confirmed


def build_report(truth, result, label, *, config=None):
    from pathlib import Path
    expected=truth.get('source',{}).get('repository')
    if expected:
        if not config or Path(config['repository']).resolve()!=Path(expected).resolve():
            raise ValueError('离线基准与任务仓库不匹配，不能套用 Juice Shop 分母')
        if config.get('pipeline_version',1)>=7 and config.get('target_adapter')!='juice_shop':
            raise ValueError('通用任务不能套用 Juice Shop 基准；需独立标注匹配的评估集')
    entries = truth['entries']
    dynamic = {entry['root_cause_id'] for entry in entries
               if entry['mode'] in {'anon', 'auth', 'reg', 'write', 'browser', 'osint'}}
    eligible = {entry['root_cause_id'] for entry in entries if entry['mode'] == 'anon'}
    candidates, behaviors = covered_roots(result)
    # Existing detectors only establish candidates or behavior, never a reviewed
    # vulnerability. No inference from signature verification or behavior labels.
    covered=set();confirmed=set()
    covered_dynamic = covered & dynamic
    covered_eligible = covered & eligible
    missing_eligible = sorted(eligible - covered)
    missing_dynamic = sorted(dynamic - covered)
    root_modes = collections.defaultdict(set)
    root_challenges = collections.defaultdict(list)
    for entry in entries:
        root_modes[entry['root_cause_id']].add(entry['mode'])
        root_challenges[entry['root_cause_id']].append(entry['challenge_key'])
    notes = {entry['root_cause_id']: entry.get('note', '') for entry in entries}

    def pct(part, whole):
        return round(len(part) / len(whole), 3) if whole else None

    report = dict(
        label=label,
        job_id=result.get('job_id'),
        status=result.get('status'),
        requests_used=result.get('requests_used'),
        stop_reason=result.get('stop_reason'),
        denominators=dict(dynamic=len(dynamic), eligible=len(eligible),
                          static=len({e['root_cause_id'] for e in entries if e['mode'] == 'static'})),
        covered=dict(dynamic=sorted(covered_dynamic), eligible=sorted(covered_eligible),
                     confirmed=sorted(confirmed),candidates=sorted(candidates & dynamic),behavior=sorted(behaviors & dynamic)),
        evaluation_status='provisional_truth_needs_independent_review',
        candidate_coverage=dict(overall=pct(candidates & dynamic,dynamic),eligible=pct(candidates & eligible,eligible)),
        coverage=dict(overall_dynamic=pct(covered_dynamic, dynamic),
                      eligible_dynamic=pct(covered_eligible, eligible)),
        missing=dict(eligible=[dict(root=root, mode=sorted(root_modes[root]),
                                    challenges=root_challenges[root], note=notes[root]) for root in missing_eligible],
                     dynamic_other=[dict(root=root, mode=sorted(root_modes[root]),
                                         challenges=root_challenges[root], note=notes[root])
                                    for root in missing_dynamic if root not in eligible]),
        targets=dict(overall_gt_50=bool(pct(covered_dynamic, dynamic) and pct(covered_dynamic, dynamic) > 0.5),
                     eligible_ge_70=bool(pct(covered_eligible, eligible) and pct(covered_eligible, eligible) >= 0.7)),
    )
    return report, entries, covered


def markdown(report, entries, covered):
    lines = ['# Juice Shop 覆盖率报告（' + report['label'] + '）', '',
             '| 指标 | 值 |', '|---|---|',
             f"| 任务 | `{report['job_id']}`（{report['status']}） |",
             f"| 请求数 | {report['requests_used']}（停止原因 {report['stop_reason']}） |",
             f"| 动态根因（总体分母） | {report['denominators']['dynamic']} |",
             f"| 覆盖根因 | {len(report['covered']['dynamic'])} |",
             f"| 总体动态覆盖率 | {report['coverage']['overall_dynamic']} |",
             f"| 固定配置内分母 | {report['denominators']['eligible']} |",
             f"| 固定配置内覆盖率 | {report['coverage']['eligible_dynamic']} |",
             f"| 已确认漏洞（不含候选和行为） | {', '.join(report['covered']['confirmed']) or '无'} |", '',
             f"候选涉及根因：{', '.join(report['covered']['candidates']) or '无'}。候选比例不属于动态确认覆盖率；旧分母保留为待独立复核基准。", '', '## 已覆盖根因', '']
    lines += [f"- `{root}`：{', '.join(sorted({e['challenge_key'] for e in entries if e['root_cause_id'] == root}))}"
              for root in report['covered']['dynamic']] or ['- 无']
    lines += ['', '## 固定配置内未覆盖（我们的缺口）', '']
    lines += [f"- `{item['root']}`（{','.join(item['mode'])}）：{'; '.join(item['challenges'])} — {item['note']}"
              for item in report['missing']['eligible']] or ['- 无']
    lines += ['', '## 配置外未覆盖（需要登录/写入/浏览器/情报/环境）', '']
    lines += [f"- `{item['root']}`（{','.join(item['mode'])}）：{'; '.join(item['challenges'])}"
              for item in report['missing']['dynamic_other']] or ['- 无']
    lines += ['', '## 118 项挑战状态', '', '| 挑战 | 模式 | 根因 | 状态 |', '|---|---|---|---|']
    covered_map = {entry['challenge_key']: entry['root_cause_id'] in covered for entry in entries}
    status = {'anon': 'eligible', 'auth': 'needs_auth', 'reg': 'needs_registration', 'write': 'needs_write',
              'browser': 'needs_browser', 'osint': 'needs_osint', 'env': 'environment_blocked',
              'static': 'static_only', 'na': 'not_a_vulnerability', 'unclear': 'needs_review'}
    for entry in entries:
        mark = 'covered' if covered_map[entry['challenge_key']] else 'not_covered'
        lines.append(f"| {entry['challenge_key']} | {status.get(entry['mode'], entry['mode'])} | {entry['root_cause_id']} | {mark} |")
    return '\n'.join(lines) + '\n'
