"""Journaled product HTTP commands. Each request has a stable stage identity."""
import json
import socket
import time
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.persistence.durable import Journal, StepUnknown, digest, workflow_lock
from vulnmind.persistence.audit import AuditError
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target
from vulnmind.tools.http import HttpRequestInput, HttpResponse
from vulnmind.tools.http_single_hop import SingleHopRequester
from vulnmind.analysis.http_broker import IsolatedHttpBroker
from vulnmind.analysis.crawler import FetchResult, crawl


def run_command(args, *, emit=True, planned_probes=None):
    from vulnmind.__main__ import _read_bounded, _planned_probes
    from vulnmind.persistence.models import Scan, Project, Approval
    from vulnmind.security.approvals import ApprovalService
    from vulnmind.analysis.validation import _classify, plan_digest
    engine = None
    started = False
    workflow_id = None
    try:
        settings = Settings()
        if args.command not in settings.enabled_http_commands or not settings.database_url:
            raise ValueError("HTTP capability or durable database unavailable")
        if not 1 <= args.max_bytes <= 1_000_000:
            raise ValueError("invalid byte limit")
        scope = Authorization.model_validate_json(_read_bounded(args.scope_file, 1_000_000))
        probes = (planned_probes if planned_probes is not None else _planned_probes(args)) if args.command == "validate-run" else []
        urls = [p.url for p in probes] if probes else [args.start if args.command == "crawl" else args.url]
        if args.command == "validate-run" and not probes:
            raise ValueError("empty probe plan")
        for url in urls:
            check_target(Target(type="web", locator=url), scope)
        workflow_id = UUID(args.approval_token) if args.command == "validate-run" else UUID(args.operation_id) if args.operation_id else uuid4()
        binding = {"version": 2, "command": args.command, "scope": scope.model_dump(mode="json"),
                   "urls": urls, "max_bytes": args.max_bytes, "actor": args.actor,
                   "distro": settings.http_broker_distro,
                   "ca_digest": None}
        broker = IsolatedHttpBroker(scope, distro=settings.http_broker_distro, max_body_bytes=args.max_bytes,
                                    ca_file=settings.http_ca_file)
        if broker.ca_pem:
            binding["ca_digest"] = digest(broker.ca_pem)
        if args.command == "crawl":
            if not 1 <= args.max_pages <= 50 or args.store and not args.project_id:
                raise ValueError("invalid crawl configuration")
            binding.update(max_pages=args.max_pages, store=args.store, project_id=args.project_id)
        if args.command == "validate-run":
            binding.update(scan_id=str(UUID(args.scan_id)), plan_digest=plan_digest(probes))
        engine = create_engine(settings.database_url)
        with Session(engine) as session:
            if args.command == "validate-run" and session.get(Scan, UUID(args.scan_id)) is None:
                raise ValueError("scan missing")
            if args.command == "validate-run":
                approval = session.get(Approval, workflow_id)
                if approval is None or approval.status not in {"approved", "consumed"}:
                    raise ValueError("approval not granted")
            if args.command == "crawl" and args.store and session.get(Project, UUID(args.project_id)) is None:
                raise ValueError("project missing")
        journal = Journal(engine, workflow_id, binding, args.actor, "web")
        last_request = 0.0

        def response(url, index=None):
            check_target(Target(type="web", locator=url), scope)
            stage = "http_" + (str(index) if index is not None else digest(url)[:40])
            def send(audit):
                nonlocal last_request
                if args.command == "validate-run":
                    with Session(engine) as session:
                        approval = session.get(Approval, workflow_id)
                        expiry = approval.expires_at if approval else None
                        if expiry is not None and expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        if (approval is None or approval.status != "consumed" or expiry is None
                                or expiry <= datetime.now(timezone.utc) or approval.scan_id != UUID(args.scan_id)
                                or approval.operation_hash != plan_digest(probes)):
                            raise ValueError("consumed approval is no longer valid")
                # Per-run pacing is supplemented by the single workflow lock.
                delay = max(0.0, .25 - (time.monotonic() - last_request))
                if delay:
                    time.sleep(delay)
                last_request = time.monotonic()
                requester = SingleHopRequester(audit,
                    resolve=lambda host: sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}),
                    transport=broker)
                return requester.request(HttpRequestInput(url=url, max_response_bytes=args.max_bytes),
                    actor=args.actor, target=Target(type="web", locator=url), scope=scope).model_dump(mode="json")
            output = journal.run(stage, {"url": url}, send)
            return HttpResponse.model_validate(output)

        def fetched(url):
            value = response(url)
            return FetchResult(status_code=value.status_code, content_type=value.headers.get("content-type", ""),
                               body=value.body.encode(), final_url=value.final_url, headers=value.headers)

        with workflow_lock(engine, workflow_id):
            started = True
            # Bind the whole command before choosing a URL-derived stage name.
            # Reusing an ID with another URL must fail before any new request.
            journal.run("http_binding", {}, lambda _: {"bound": True}, replay_safe=True)
            if args.command == "validate-run":
                def approve(session, output):
                    key = plan_digest(probes)
                    if not ApprovalService(session).consume_bound(args.approval_token, scan_id=UUID(args.scan_id),
                            action="validation.probes", target=key, operation_hash=key):
                        raise ValueError("valid bound approval required")
                    return {"approved": True}
                journal.run("http_approval", {"plan": plan_digest(probes)}, lambda _: {}, persist=approve, replay_safe=True)
                results = []
                for index, probe in enumerate(probes):
                    value = response(probe.url, index)
                    item = FetchResult(status_code=value.status_code, content_type=value.headers.get("content-type", ""),
                                       body=value.body.encode(), final_url=value.final_url, headers=value.headers)
                    results.append(_classify(probe, item).model_dump(mode="json"))
                payload = {"status": "completed", "results": results, "approval_digest": plan_digest(probes),
                    **{key: sum(x["verdict"] == value for x in results)
                       for key, value in (("candidates", "candidate"), ("inconclusive", "inconclusive"), ("errors", "error"))}}
            elif args.command == "fetch":
                value = response(args.url)
                payload = {"status": "ok", "status_code": value.status_code, "headers": value.headers,
                           "final_url": value.final_url, "body": value.body[:2000], "body_bytes": len(value.body.encode()),
                           "truncated": value.truncated}
            else:
                result = crawl(start=Target(type="web", locator=args.start), scope=scope, fetch=fetched,
                               max_pages=args.max_pages, max_page_bytes=args.max_bytes)
                payload = {"status": "ok", "pages": [p.url for p in result.pages], "endpoints": result.endpoints[:200],
                           "endpoint_count": len(result.endpoints), "findings": result.findings[:200],
                           "finding_count": len(result.findings), "out_of_scope": result.out_of_scope,
                           "errors": result.errors[:20], "skipped": result.skipped, "truncated": result.truncated}
                if args.store:
                    def store(session, output):
                        from vulnmind.analysis.crawl_store import store_crawl_result
                        scan = store_crawl_result(session=session, project_id=UUID(args.project_id), actor=args.actor,
                                                  endpoints=result.endpoints)
                        return {"scan_id": str(scan.id)}
                    payload.update(journal.run("http_store", {"endpoints": result.endpoints}, lambda _: {},
                                               persist=store, replay_safe=True))
            payload = journal.run("http_result", payload, lambda _: payload, replay_safe=True)
    except Exception:
        payload = {"status": "unknown" if started else "blocked",
                   "errors": ["inspect workflow-status and audit; resume using this operation ID; uncertain requests are not resent"]}
    finally:
        if engine is not None:
            engine.dispose()
    if workflow_id is not None:
        payload = {**payload, "operation_id": str(workflow_id)}
    if not emit:
        return payload
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if payload["status"] in {"ok", "completed"} else 2
