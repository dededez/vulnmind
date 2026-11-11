"""Resumable discovery -> plan -> approval -> probes -> evidence -> report loop.

Approval waits are normal states. Nested HTTP operations own their own receipts,
so an interrupted coordinator may resume without resetting an uncertain send.
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.persistence.durable import Journal, workflow_lock, StepUnknown
from vulnmind.persistence.models import Approval, WebEndpoint, Scan
from vulnmind.analysis.validation import Probe, plan_probes, plan_digest
from vulnmind.security.approvals import ApprovalService
from vulnmind.schemas import Target
from vulnmind.security.scope import check_target


class WebLoop:
    def __init__(self, engine, workflow_id, project_id, scope, options, *, http=None, runtime=None, external=None):
        from vulnmind.analysis.durable_http import run_command
        self.engine, self.id, self.project = engine, workflow_id, project_id
        self.scope, self.options = scope, options
        self.http, self.runtime = http or run_command, runtime
        self.external = external
        self.actor = options['actor']
        self.journal = Journal(engine, workflow_id, dict(version=2, project=str(project_id),
            scope=scope.model_dump(mode='json'), options=options), self.actor, 'web')

    def external_service(self):
        if self.external is not None:
            return self.external
        from pathlib import Path
        from vulnmind.config import Settings
        from vulnmind.workbench.external import ExternalWorkbench
        settings = Settings()
        ext_root = Path(self.options['report_root']).resolve().parent / 'workbench' / 'external'
        if not (ext_root / 'validation.json').is_file():
            fallback = Path(__file__).resolve().parents[3] / '.vulnmind-workbench' / 'external'
            if (fallback / 'validation.json').is_file():
                ext_root = fallback
        self.external = ExternalWorkbench(ext_root, distro=settings.http_broker_distro)
        return self.external

    def execute_external_probes(self, scan, approval, probes):
        from urllib.parse import urlsplit
        from vulnmind.persistence.audit import SessionAuditSink
        with Session(self.engine) as session:
            audit = SessionAuditSink(session)
            approvals = ApprovalService(session)
            if not approvals.consume_bound(approval['approval_id'], scan_id=scan,
                                           action='validation.probes', target=approval['digest'],
                                           operation_hash=approval['digest']):
                session.rollback()
                raise StepUnknown('approval consumption rejected for ' + approval['approval_id'])
            audit.record({'call_id': str(uuid5(self.id, 'mcp-validate-' + approval['approval_id'])),
                          'tool_name': 'web.validation.mcp', 'actor': self.actor,
                          'target_type': 'web', 'status': 'started'})
            session.commit()
        service = self.external_service()
        results = []
        candidates = 0
        for probe in probes:
            parsed = urlsplit(probe.url)
            origin = f'{parsed.scheme}://{parsed.netloc}'
            tool_id = ('hexstrike.sqlmap_scan' if probe.kind == 'sql_error'
                       else 'hexstrike.dalfox_xss_scan' if probe.kind in {'reflection', 'xss_reflection'}
                       else 'hexstrike.nuclei_scan')
            args = ({'target': probe.url, 'template': 'http/misconfiguration/missing-security-headers.yaml'}
                    if tool_id == 'hexstrike.nuclei_scan' else {'url': probe.url})
            prepared = service.prepare(dict(
                tool_id=tool_id,
                arguments=args,
                scope=dict(origins=[origin], networks=list(self.scope.allowed_ip_networks)),
                budget=dict(requests=8, connections=8, seconds=30),
            ))
            out = service.execute(prepared['plan']['execution_id'], prepared['digest'])['execution']
            res = out.get('result') or {}
            stdout = (res.get('stdout') or '').lower()
            verdict = 'inconclusive'
            detail = f'MCP {tool_id} executed ({res.get("requests_used", 1)} requests); no candidate signal'
            if tool_id == 'hexstrike.sqlmap_scan' and any(m in stdout for m in ('is vulnerable', 'injectable', 'payload:')):
                verdict = 'candidate'
                detail = 'MCP SQLMap reported SQL injection candidate; manual verification required'
            elif tool_id == 'hexstrike.dalfox_xss_scan' and ('"poc"' in stdout or 'reflected' in stdout):
                verdict = 'candidate'
                detail = 'MCP Dalfox reported reflection/XSS candidate; not proof of script execution'
            elif tool_id == 'hexstrike.nuclei_scan' and stdout.strip():
                verdict = 'candidate'
                detail = 'MCP Nuclei matched fixed template; review configuration'
            if verdict == 'candidate':
                candidates += 1
            results.append(dict(
                kind=probe.kind,
                url=probe.url,
                verdict=verdict,
                detail=detail,
                external_tool=tool_id,
                mcp_execution_id=prepared['plan']['execution_id'],
                mcp_result_sha256=out.get('result_sha256'),
            ))
        return dict(
            status='completed',
            results=results,
            candidates=candidates,
            inconclusive=len(results) - candidates,
            errors=0,
            approval_digest=approval['digest'],
        )

    def invoke_http(self, command, operation, **kw):
        args = SimpleNamespace(command=command, operation_id=str(operation), actor=self.actor,
            scope_file=self.options['scope_file'], max_bytes=self.options['max_bytes'], **kw)
        result = self.http(args, emit=False)
        if result['status'] not in {'ok', 'completed'}:
            raise StepUnknown('inspect nested HTTP operation ' + str(operation))
        return result

    def run(self):
        opts = self.options
        if not 1 <= opts['rounds'] <= 3:
            raise ValueError('rounds must be 1..3')
        check_target(Target(type='web', locator=opts['start']), self.scope)
        with workflow_lock(self.engine, self.id):
            crawl = self.journal.run('discover', {}, lambda _: self.invoke_http('crawl', uuid5(self.id, 'crawl'),
                start=opts['start'], max_pages=opts['max_pages'], store=True, project_id=str(self.project)), replay_safe=True)
            scan = UUID(crawl['scan_id'])
            def discoveries(session, _):
                from vulnmind.analysis.persistence import FindingWriter
                from vulnmind.findings import FindingCandidate, group_findings
                candidates=[FindingCandidate.model_validate(item) for item in crawl.get('findings', [])]
                FindingWriter(session).store_groups(scan,group_findings(candidates))
                return {'stored':len(candidates), 'omitted':max(0,crawl.get('finding_count',len(candidates))-len(candidates))}
            self.journal.run('discovery_findings',crawl,lambda _: {},persist=discoveries,replay_safe=True)
            with Session(self.engine) as session:
                urls = sorted(set([opts['start'], *session.scalars(select(WebEndpoint.url).where(WebEndpoint.scan_id == scan))]))[:2000]
            previous, attempted = [], set()
            for number in range(opts['rounds']):
                prefix = f'round_{number}'
                def plan(audit):
                    available = [p for p in plan_probes(urls) if (p.kind, p.url) not in attempted]
                    if opts.get('agent_plan') and available:
                        from vulnmind.agents.runtime import AgentRuntime
                        from vulnmind.agents.audit import AgentAuditBridge
                        from vulnmind.agents.deepseek import DeepSeekClient
                        from vulnmind.agents.prompts import WEB_VALIDATOR
                        from vulnmind.agents.validation_plan import ValidationPlanDraft
                        from vulnmind.context.builder import ContextItem
                        runtime = self.runtime or AgentRuntime(DeepSeekClient(), AgentAuditBridge(audit, target_type='web'))
                        selected = runtime.run(WEB_VALIDATOR, actor=self.actor, schema=ValidationPlanDraft,
                            task='Select at most 5 remaining probe indexes using prior results; empty selections stop investigation. Never claim exploitability.',
                            context=[ContextItem(ref='previous', kind='execution', text=json.dumps(previous)[:12000]),
                                ContextItem(ref='remaining', kind='execution', text=json.dumps([dict(index=i, kind=p.kind) for i,p in enumerate(available)]))])
                        indexes = list(dict.fromkeys(s.index for s in selected.data.selections))
                        if any(i >= len(available) for i in indexes):
                            raise ValueError('invalid planner index')
                        available = [available[i] for i in indexes[:5]]
                    return {'probes': [p.model_dump(mode='json') for p in available[:5]]}
                planned = self.journal.run(prefix+'_plan', {'previous': previous}, plan)
                probes = [Probe.model_validate(p) for p in planned['probes']]
                if not probes:
                    break
                key = plan_digest(probes)
                def request(session, output):
                    row = ApprovalService(session).request(scan_id=scan, action='validation.probes', target=key, operation_hash=key)
                    session.flush()
                    return {'approval_id': str(row.id), 'digest': key}
                approval = self.journal.run(prefix+'_approval', planned, lambda _: {}, persist=request, replay_safe=True)
                with Session(self.engine) as session:
                    row = session.get(Approval, UUID(approval['approval_id']))
                    if row.status == 'pending':
                        return dict(status='waiting_approval', workflow_id=str(self.id), scan_id=str(scan), round=number,
                                    **approval, probes=planned['probes'])
                    if row.status not in {'approved', 'consumed'}:
                        return dict(status='blocked', workflow_id=str(self.id), reason='approval denied')
                def execute(_):
                    if opts.get('external_tools'):
                        return self.execute_external_probes(scan, approval, probes)
                    args = SimpleNamespace(command='validate-run', scan_id=str(scan), approval_token=approval['approval_id'],
                        scope_file=opts['scope_file'], max_bytes=opts['max_bytes'], actor=self.actor)
                    result = self.http(args, emit=False, planned_probes=probes)
                    if result['status'] != 'completed':
                        raise StepUnknown('inspect validation operation '+approval['approval_id'])
                    return result
                result = self.journal.run(prefix+'_validate', approval, execute, replay_safe=True)
                self.journal.run(prefix+'_evidence', result, lambda _: result,
                                 persist=lambda s,v: self.store(s, scan, v), replay_safe=True)
                self.journal.run(prefix+'_report', result, lambda _: {},
                                 persist=lambda s,v: self.report(s, scan), replay_safe=True)
                previous += result['results']
                attempted.update((p.kind,p.url) for p in probes)
                # A round without a signal does not justify additional probing.
                if not result['candidates']:
                    break
            final = self.journal.run('final_report', {'results': previous}, lambda _: {},
                                     persist=lambda s,v: self.report(s, scan), replay_safe=True)
            from vulnmind.reports.store import ReportStore
            from vulnmind.reports.identity import matches_scan
            from vulnmind.evidence.store import EvidenceStore
            from vulnmind.persistence.models import Evidence, Finding
            from pathlib import Path
            import hashlib
            content=ReportStore(opts['report_root']).read(final['report_uri'])
            if not matches_scan(content,'json',scan_id=scan,project_id=self.project):
                raise ValueError('report identity changed')
            with Session(self.engine) as session:
                actual={str(e.id):e for e in session.scalars(select(Evidence).join(Finding,Evidence.finding_id==Finding.id).where(Finding.scan_id==scan))}
                if set(actual)!={item['id'] for item in final['evidence']}:
                    raise ValueError('evidence set changed')
                for item in final['evidence']:
                    row=actual[item['id']]
                    if row.hash!=item['hash'] or row.content_ref!=item['uri'] or hashlib.sha256(EvidenceStore(Path(opts['evidence_root'])).read(row.content_ref)).hexdigest()!=row.hash:
                        raise ValueError('evidence integrity failed')
            return dict(status='finished', workflow_id=str(self.id), scan_id=str(scan), **final)

    def store(self, session, scan, value):
        from pathlib import Path
        from vulnmind.findings import FindingCandidate, group_findings
        from vulnmind.analysis.persistence import FindingWriter
        from vulnmind.evidence.ingest import ingest_evidence, EvidenceItem
        from vulnmind.evidence.store import EvidenceStore
        items, candidates = [], []
        for result in value['results']:
            candidate = FindingCandidate(title=f"{result['kind']}: {result['verdict']}", vulnerability_type=result['kind'],
                target_id='web', location=result['url'], source_tool=result.get('external_tool') or 'scoped_validation',
                status='unverified' if result['verdict']=='candidate' else 'insufficient_evidence', severity='unknown')
            candidates.append(candidate)
            items.append(EvidenceItem(fingerprint=candidate.fingerprint(), content=json.dumps(result).encode(),
                evidence_type='validation_result', locator=result['url'][:1000]))
        FindingWriter(session).store_groups(scan, group_findings(candidates))
        evidence = ingest_evidence(session, EvidenceStore(Path(self.options['evidence_root'])), scan_id=scan, items=items)
        return {'stored': evidence.stored, 'results': value['results']}

    def report(self, session, scan):
        from pathlib import Path
        from vulnmind.reports.regenerate import ReportRegenerator
        from vulnmind.reports.store import ReportStore
        from vulnmind.persistence.models import Evidence,Finding
        has_probes=session.scalar(select(Evidence.id).join(Finding,Evidence.finding_id==Finding.id).where(Finding.scan_id==scan,Evidence.evidence_type=='validation_result').limit(1)) is not None
        result = ReportRegenerator(session, ReportStore(Path(self.options['report_root']))).regenerate(scan, report_format='json', actor=self.actor,
            validation_context=dict(workflow_id=str(self.id),interpretation='bounded_probe_observations_not_exploitability_proof') if has_probes else None)
        from vulnmind.reports.signing import sign_configured
        sign_configured(ReportStore(Path(self.options['report_root'])), result.reference.uri)
        from vulnmind.persistence.models import Evidence,Finding
        rows=session.scalars(select(Evidence).join(Finding,Evidence.finding_id==Finding.id).where(Finding.scan_id==scan))
        return {'report_uri': result.reference.uri,'evidence':sorted([dict(id=str(e.id),hash=e.hash,uri=e.content_ref) for e in rows],key=lambda r:r['id'])}
