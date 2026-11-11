"""Product CLI for journaled workflows and explicit recovery decisions."""
import hashlib
import json
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.persistence.durable import StepUnknown, recover_step
from vulnmind.persistence.models import Project
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target


def run_repository(args):
    from vulnmind.graph.durable_repository import RepositoryFlow
    from vulnmind.agents.deepseek import DEFAULT_MODEL
    from vulnmind.analysis.repo_analyzers import MAX_REPORT_BYTES
    from vulnmind.__main__ import _read_bounded
    engine = None
    started = False
    try:
        settings = Settings()
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root required")
        workflow_id, project_id = UUID(args.workflow_id), UUID(args.project_id)
        target = Target(type="repository", locator=str(args.repository.resolve(strict=True)))
        scope = Authorization.model_validate_json(_read_bounded(args.scope_file, 1_000_000))
        check_target(target, scope)
        reports = {}
        for name, file in (("semgrep_sarif", args.semgrep_sarif), ("bandit_json", args.bandit_json)):
            if file:
                path = file.resolve(strict=True)
                with path.open("rb") as stream:
                    content = stream.read(MAX_REPORT_BYTES + 1)
                if len(content) > MAX_REPORT_BYTES:
                    raise ValueError("report too large")
                reports[name] = {"path": str(path), "sha256": hashlib.sha256(content).hexdigest()}
        tools = sorted([*reports, *(["gitleaks_sandbox"] if args.gitleaks_sandbox else []),
                        *(["trivy_sandbox"] if args.trivy_sandbox else []),
                        *(["checkov_mcp"] if getattr(args, "checkov_mcp", False) else [])])
        opts = {"actor": args.actor, "tools": tools, "reports": reports, "report_format": args.report_format,
                "report_root": str(Path(settings.report_root).resolve()),
                "evidence_root": str(Path(settings.evidence_root).resolve()) if settings.evidence_root else None,
                "agent_model": args.agent_model or DEFAULT_MODEL,
                **{key: getattr(args, key) for key in ("agent_plan", "agent_analysis", "agent_review", "agent_report",
                                                      "knowledge_context", "agent_knowledge")}}
        if args.skills:
            opts['skills'] = str(args.skills.resolve(strict=True))
        if args.use_memory:
            opts['use_memory'] = True
        if not args.actor.strip() or len(args.actor) > 255 or any(ord(c) < 32 for c in args.actor):
            raise ValueError("invalid actor")
        engine = create_engine(settings.database_url)
        if (args.knowledge_context or args.agent_knowledge) and engine.dialect.name != "postgresql":
            raise ValueError("knowledge requires PostgreSQL")
        with Session(engine) as session:
            if session.get(Project, project_id) is None:
                raise ValueError("project missing")
        flow = RepositoryFlow(engine, workflow_id, project_id, target, scope, opts)
        started = True
        payload = flow.run(pause_after=args.pause_after, reconcile=args.reconcile)
    except Exception:
        payload = {"status": "unknown" if started else "blocked", "workflow_id": getattr(args, "workflow_id", None),
                   "errors": ["inspect workflow-status; resume with the same inputs or explicitly recover an interrupted stage"]}
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if payload["status"] in {"finished", "paused"} else 2


def recover(args):
    engine = None
    try:
        url = Settings().database_url
        if not url:
            raise ValueError("database required")
        engine = create_engine(url)
        payload = recover_step(engine, UUID(args.workflow_id), args.stage, args.action, args.actor,
                               args.reason, args.acknowledge_possible_repeat)
    except Exception:
        payload = {"status": "blocked", "errors": ["recovery rejected; inspect the stage and stop any active worker"]}
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(payload))
    return 2 if payload["status"] == "blocked" else 0


def run_web(args):
    from vulnmind.graph.web_loop import WebLoop
    from vulnmind.schemas import Authorization
    from vulnmind.__main__ import _read_bounded
    engine = None
    try:
        settings = Settings()
        if not settings.database_url or not settings.evidence_root or not settings.report_root:
            raise ValueError('database and artifact stores required')
        scope = Authorization.model_validate_json(_read_bounded(args.scope_file, 1000000))
        options = {k: getattr(args, k) for k in ('actor', 'start', 'rounds', 'max_pages', 'max_bytes', 'agent_plan')}
        if getattr(args, 'external_tools', False):
            options['external_tools'] = True
        options.update(scope_file=str(args.scope_file.resolve()), report_root=settings.report_root, evidence_root=settings.evidence_root)
        engine = create_engine(settings.database_url)
        result = WebLoop(engine, UUID(args.workflow_id), UUID(args.project_id), scope, options).run()
    except Exception:
        result = dict(status='unknown', workflow_id=args.workflow_id,
                      errors=['inspect workflow-status and child operation receipts; resume the same command'])
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['status'] in {'finished', 'waiting_approval'} else 2


def promote_memory(args):
    from datetime import datetime, timezone
    from uuid import uuid4
    from vulnmind.memory.manager import MemoryRecord
    from vulnmind.persistence.models import MemoryRecordRow
    from vulnmind.persistence.repositories import MemoryRepository
    from vulnmind.persistence.audit import SessionAuditSink
    engine = None
    try:
        if not args.actor.strip() or not 1 <= len(args.content) <= 4000:
            raise ValueError('actor and bounded content required')
        engine = create_engine(Settings().database_url)
        with Session(engine) as session, session.begin():
            source = session.get(MemoryRecordRow, UUID(args.source_id))
            now = datetime.now(timezone.utc)
            if source is None or source.invalidated:
                raise ValueError('source unavailable')
            expiry = source.expires_at
            if expiry and (expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry) <= now:
                raise ValueError('source expired')
            record = MemoryRecord(id=uuid4(), level='long_term', project_id=str(source.project_id),
                content=args.content, source_refs=(f'memory:{source.id}',), confidence=0.0, validated_by=args.actor)
            MemoryRepository(session).save(record)
            SessionAuditSink(session).record(dict(call_id=str(record.id), tool_name='memory.promote', actor=args.actor,
                target_type='repository', status='succeeded'))
            result = dict(status='stored', memory_id=str(record.id))
    except Exception:
        result = dict(status='blocked', errors=['memory promotion rejected'])
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(result))
    return 0 if result['status']=='stored' else 2


def run_attestation(args):
    from vulnmind.analysis.attestation import attest
    from vulnmind.reports.signing import resolve_signing_key
    engine=None
    try:
        settings=Settings()
        key,_=resolve_signing_key(key=settings.report_signing_key,key_file=settings.report_signing_key_file)
        engine=create_engine(settings.database_url)
        operation=UUID(args.attestation_id)
        value=attest(engine,operation,UUID(args.scan_id),args.fingerprint,args.verdict,
            [UUID(i) for i in args.evidence_id],args.actor,args.reason,settings.evidence_root,key)
        from vulnmind.persistence.durable import Journal, workflow_lock
        journal=Journal(engine,operation,value['statement'],args.actor)
        from vulnmind.reports.regenerate import ReportRegenerator
        from vulnmind.reports.store import ReportStore
        def report(session, _):
            rebuilt=ReportRegenerator(session,ReportStore(Path(settings.report_root))).regenerate(UUID(args.scan_id),report_format='json',actor=args.actor)
            return {'report_uri':rebuilt.reference.uri}
        with workflow_lock(engine,operation):
            result=journal.run('attestation_report',{},lambda _: {},persist=report,replay_safe=True)
        result=dict(status='attested',attestation_id=str(operation),**result)
    except Exception:
        result=dict(status='blocked',errors=['attestation rejected; inspect evidence and stage receipts'])
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(result))
    return 0 if result['status']=='attested' else 2
