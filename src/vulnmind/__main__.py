"""Command line entry point for explicitly labeled simulation and stored reports."""
import argparse
import asyncio
import json
from pathlib import Path
from uuid import UUID, uuid4

from vulnmind.findings import group_findings
from vulnmind.graph.mock_workflow import build_mock_graph
from vulnmind.reports.generator import DecisionSummary, ReportInput, generate
from vulnmind.schemas import ScanRequest
from vulnmind.tools.adapters import AdapterError, parse_gitleaks, parse_sarif
from vulnmind.analysis.triage import triage_groups

_MAX_REQUEST_BYTES = 1_000_000


class _EphemeralAudit:
    """A simulation-only event counter; it is not a persistent audit log."""
    def __init__(self):
        self.count = 0

    def record(self, event: dict) -> None:
        self.count += 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="vulnmind")
    parser.add_argument("--version", action="version", version="VulnMind 0.2.0 (workbench v6)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ui = subparsers.add_parser("ui", help="Open the local unified investigation workbench")
    ui.add_argument("--port", type=int, default=8765)
    simulate = subparsers.add_parser("simulate", help="Run a no-scan simulation using a JSON request")
    simulate.add_argument("--request", required=True, type=Path, help="Path to JSON input; do not include credentials")
    analyze = subparsers.add_parser("analyze", help="Render a report from existing scanner output")
    analyze.add_argument("--sarif", type=Path, help="SARIF 2.1 document produced elsewhere")
    analyze.add_argument("--gitleaks", type=Path, help="Gitleaks JSON report produced elsewhere")
    analyze.add_argument("--scan-id", required=True, help="Scan identifier used in the report")
    analyze.add_argument("--project-id", required=True, help="Project identifier used in the report")
    analyze.add_argument("--target-id", default="repository", help="Target identifier recorded on findings")
    analyze.add_argument("--format", choices=("markdown", "json"), default="markdown")
    analyze.add_argument("--output", type=Path, help="Write the report here instead of stdout")
    report = subparsers.add_parser("report", help="Print a stored report for a scan")
    report.add_argument("--scan-id", required=True, help="Scan UUID whose report should be read")
    report.add_argument("--json", action="store_true", help="Wrap the output in a JSON envelope")
    project_create = subparsers.add_parser("project-create", help="Create a project for authorized scans")
    project_create.add_argument("--name", required=True, help="Project name (1 to 255 characters)")
    project_create.add_argument("--actor", default="cli")
    approvals = subparsers.add_parser("approvals", help="List or decide pending approvals")
    approvals_sub = approvals.add_subparsers(dest="approvals_command", required=True)
    approvals_list = approvals_sub.add_parser("list", help="List pending approvals for a scan")
    approvals_list.add_argument("--scan-id", required=True, help="Scan UUID to inspect")
    approvals_decide = approvals_sub.add_parser("decide", help="Approve or deny one request")
    approvals_decide.add_argument("--id", required=True, help="Approval UUID")
    approvals_decide.add_argument("--approver", required=True, help="Name recorded on the decision")
    approvals_decide.add_argument("--deny", action="store_true", help="Deny instead of approving")
    approvals_decide.add_argument("--credential", help="HMAC or SSH signature credential")
    approvals_decide.add_argument("--local-owner", action="store_true",
                                  help="Explicitly sign this exact decision using the configured local HMAC owner key")
    scans = subparsers.add_parser("scans", help="List scans for a project")
    scans.add_argument("--project-id", required=True, help="Project UUID to list scans for")
    scans.add_argument("--limit", type=int, default=20, help="Maximum number of scans to show")
    verify = subparsers.add_parser("verify", help="Verify stored report and evidence integrity")
    verify.add_argument("--scan-id", required=True, help="Scan UUID to verify")
    findings = subparsers.add_parser("findings", help="List findings for a scan")
    findings.add_argument("--scan-id", required=True, help="Scan UUID to inspect")
    findings.add_argument("--limit", type=int, default=200, help="Maximum findings to show")
    feedback = subparsers.add_parser("finding-feedback",
                                     help="Record an operator verdict for one stored finding")
    feedback.add_argument("--scan-id", required=True, help="Scan UUID the finding belongs to")
    feedback.add_argument("--fingerprint", required=True, help="Finding fingerprint from `findings`")
    feedback.add_argument("--verdict", required=True,
                          choices=("false_positive", "confirmed", "accepted_risk", "needs_more_info"))
    feedback.add_argument("--note", help="Optional short rationale; no secrets or target data")
    feedback.add_argument("--actor", default="cli")
    feedback_list = subparsers.add_parser("feedback", help="List the newest operator verdicts for a scan")
    feedback_list.add_argument("--scan-id", required=True, help="Scan UUID to inspect")
    feedback_list.add_argument("--limit", type=int, default=500, help="Maximum verdicts to show")
    report_regenerate = subparsers.add_parser(
        "report-regenerate", help="Rebuild a stored report with the newest operator verdicts")
    report_regenerate.add_argument("--scan-id", required=True, help="Scan UUID to rebuild")
    report_regenerate.add_argument("--report-format", choices=("markdown", "json"), default="markdown")
    report_regenerate.add_argument("--actor", default="cli")
    report_sign = subparsers.add_parser("report-sign",
                                        help="Attach an HMAC signature to the latest stored report")
    report_sign.add_argument("--scan-id", required=True, help="Scan UUID whose report should be signed")
    report_sign.add_argument("--actor", default="cli")
    report_verify = subparsers.add_parser("report-verify",
                                          help="Verify the latest stored report signature")
    report_verify.add_argument("--scan-id", required=True, help="Scan UUID whose report should be verified")
    evidence = subparsers.add_parser("evidence", help="List evidence references for a scan")
    evidence.add_argument("--scan-id", required=True, help="Scan UUID to inspect")
    agent = subparsers.add_parser("agent-run", help="Run one DeepSeek agent with the built-in prompts")
    agent.add_argument("--role", choices=("scan-planner", "repository-analyst", "triage-reviewer",
                                          "report-writer"), default="triage-reviewer")
    agent.add_argument("--task", required=True)
    agent.add_argument("--context-file", type=Path, help="JSON array of {ref, kind, text} references")
    agent.add_argument("--actor", default="cli")
    agent.add_argument("--model", default=None, help="Override the DeepSeek model name")
    rag = subparsers.add_parser("knowledge-ask", help="Retrieve knowledge and ask a model with citations")
    rag.add_argument("--question", required=True, help="Question sent to the configured model")
    rag.add_argument("--send-to-model", action="store_true", help="Explicitly allow sending selected knowledge to the model service")
    rag.add_argument("--retrieval", choices=("hybrid",), default="hybrid")
    rag.add_argument("--actor", default="cli")
    rag.add_argument("--output", type=Path, help="Save answer and citation IDs as a new JSON file; never overwrite")
    crawl = subparsers.add_parser("crawl", help="GET-only scoped crawl through the WSL sandbox")
    crawl.add_argument("--start", required=True, help="Authorized absolute http(s) start URL")
    crawl.add_argument("--scope-file", required=True, type=Path, help="JSON Authorization document")
    crawl.add_argument("--max-pages", type=int, default=10)
    crawl.add_argument("--max-bytes", type=int, default=200_000)
    crawl.add_argument("--actor", default="cli")
    crawl.add_argument("--store", action="store_true", help="Persist endpoints as a crawl-mode scan")
    crawl.add_argument("--project-id", help="Existing project UUID (required with --store)")
    crawl.add_argument("--operation-id", help="Stable UUID used to resume without repeating completed requests")
    endpoints = subparsers.add_parser("endpoints", help="List stored web endpoints for a scan")
    endpoints.add_argument("--scan-id", required=True, help="Scan UUID to inspect")
    endpoints.add_argument("--limit", type=int, default=500, help="Maximum endpoints to show")
    shell_request = subparsers.add_parser("shell-request",
                                          help="Record a pending approval bound to one sandboxed command")
    shell_request.add_argument("--scan-id", required=True, help="Scan UUID the approval belongs to")
    shell_request.add_argument("--cwd", required=True, help="Absolute directory inside the repository")
    shell_request.add_argument("--argv", action="append", required=True,
                               help="One argument; repeat in order, the first is the program")
    shell_request.add_argument("--purpose", default="operator-requested read-only command")
    shell_request.add_argument("--timeout", type=int, default=120)
    shell_request.add_argument("--env", action="append", default=[], help="Environment name to forward")
    shell_run = subparsers.add_parser("shell-run",
                                      help="Run an approved read-only command in the WSL sandbox")
    shell_run.add_argument("--scan-id", required=True, help="Scan UUID the approval belongs to")
    shell_run.add_argument("--repository", required=True, type=Path,
                           help="Authorized repository root that will be mounted read-only")
    shell_run.add_argument("--cwd", required=True, help="Absolute directory inside the repository")
    shell_run.add_argument("--argv", action="append", required=True,
                           help="One argument; repeat in order, the first is the program")
    shell_run.add_argument("--approval-token", required=True, help="Approval UUID from shell-request")
    shell_run.add_argument("--scope-file", required=True, type=Path, help="JSON Authorization document")
    shell_run.add_argument("--purpose", default="operator-requested read-only command")
    shell_run.add_argument("--timeout", type=int, default=120)
    shell_run.add_argument("--env", action="append", default=[], help="Environment name to forward")
    shell_run.add_argument("--actor", default="cli")
    shell_run.add_argument("--max-output-bytes", type=int, default=200_000)
    validate_request = subparsers.add_parser("validate-request",
                                             help="Record a pending approval bound to a validation plan")
    validate_request.add_argument("--scan-id", required=True, help="Scan UUID the approval belongs to")
    validate_request.add_argument("--url", action="append", default=[],
                                  help="Authorized endpoint URL with query parameters; repeat as needed")
    validate_request.add_argument("--plan-file", type=Path,
                                  help="Plan JSON from validation-plan; mutually exclusive with --url")
    validate_run = subparsers.add_parser("validate-run",
                                         help="Run approved non-destructive web validation probes")
    validate_run.add_argument("--scan-id", required=True, help="Scan UUID the approval belongs to")
    validate_run.add_argument("--url", action="append", default=[],
                              help="Authorized endpoint URL with query parameters; repeat as needed")
    validate_run.add_argument("--plan-file", type=Path,
                              help="Plan JSON from validation-plan; mutually exclusive with --url")
    validate_run.add_argument("--scope-file", required=True, type=Path, help="JSON Authorization document")
    validate_run.add_argument("--approval-token", required=True, help="Approval UUID from validate-request")
    validate_run.add_argument("--actor", default="cli")
    validate_run.add_argument("--max-bytes", type=int, default=200_000)
    validation_plan = subparsers.add_parser(
        "validation-plan", help="Ask the model to select probes from stored endpoints (no request is sent)")
    validation_plan.add_argument("--scan-id", required=True, help="Web scan UUID whose endpoints are used")
    validation_plan.add_argument("--limit", type=int, default=500, help="Maximum stored endpoints to read")
    validation_plan.add_argument("--max-selections", type=int, default=10,
                                 help="Maximum probes the model may select (1-10)")
    validation_plan.add_argument("--agent-model", default=None, help="Override the DeepSeek model")
    validation_plan.add_argument("--output", type=Path,
                                 help="Write the plan JSON here for validate-request --plan-file")
    validation_plan.add_argument("--actor", default="cli")
    gc = subparsers.add_parser("evidence-gc", help="Remove unreferenced evidence files (dry run by default)")
    gc.add_argument("--apply", action="store_true", help="Actually delete orphaned files")
    gc.add_argument("--grace-hours", type=float, default=24.0, help="Only delete files older than this")
    audit_verify = subparsers.add_parser("audit-verify", help="Recompute the audit hash chain")
    audit_verify.add_argument("--limit", type=int, default=2000, help="Maximum events to check")
    audit_trace = subparsers.add_parser("audit-trace", help="Inspect a repository or web scan audit correlation ID")
    audit_trace.add_argument("--call-id", required=True, help="Scan audit correlation UUID")
    audit_trace.add_argument("--limit", type=int, default=2000, help="Maximum events to return")
    audit_recent = subparsers.add_parser("audit-recent", help="List recent repository and web scan audits, including unknown outcomes")
    audit_recent.add_argument("--limit", type=int, default=20, help="Maximum scans to return (1-100)")
    doctor = subparsers.add_parser("doctor", help="Read-only configuration and integrity self-check")
    scan = subparsers.add_parser("scan", help="Run the built-in repository analysis and store a report")
    scan.add_argument("--repository", required=True, type=Path, help="Directory inside the authorized roots")
    scan.add_argument("--project-id", required=True, help="Existing project UUID")
    scan.add_argument("--scope-file", required=True, type=Path,
                      help="JSON Authorization document; do not include credentials")
    scan.add_argument("--actor", default="cli", help="Actor recorded in the audit trail")
    scan.add_argument("--report-format", choices=("markdown", "json"), default="markdown")
    scan.add_argument("--skills", type=Path, help="Skill directory used to record a context manifest")
    scan.add_argument("--knowledge-context", action="store_true",
                      help="Select PostgreSQL FTS knowledge for a post-analysis manifest; no model is invoked")
    scan.add_argument("--gitleaks", type=Path, help="Host execution is disabled; use --gitleaks-sandbox")
    scan.add_argument("--gitleaks-sandbox", action="store_true", help="Run Gitleaks inside the WSL sandbox (no network)")
    scan.add_argument("--trivy-sandbox", action="store_true", help="Temporarily unavailable: isolated Trivy runner is required")
    scan.add_argument("--semgrep-sarif", type=Path,
                      help="Ingest a SARIF report produced by Semgrep elsewhere (no execution)")
    scan.add_argument("--bandit-json", type=Path,
                      help="Ingest a Bandit JSON report produced elsewhere (no execution)")
    scan.add_argument("--agent-review", action="store_true",
                      help="Ask the DeepSeek triage reviewer for advisory (unverified) opinions")
    scan.add_argument("--agent-plan", action="store_true",
                      help="Let the model select only among explicitly enabled repository analyzers")
    scan.add_argument("--agent-knowledge", action="store_true",
                      help="Send selected knowledge to the model for advisory guidance; requires --agent-review")
    scan.add_argument("--agent-model", default=None, help="Override the DeepSeek model for --agent-review")
    workflow_scan = subparsers.add_parser("workflow-scan", help="Run a single-attempt repository workflow")
    workflow_scan.add_argument("--workflow-id", required=True, help="Stable UUID for this workflow")
    workflow_scan.add_argument("--repository", required=True, type=Path)
    workflow_scan.add_argument("--project-id", required=True)
    workflow_scan.add_argument("--scope-file", required=True, type=Path)
    workflow_scan.add_argument("--actor", default="cli")
    workflow_scan.add_argument("--report-format", choices=("markdown", "json"), default="markdown")
    workflow_scan.add_argument("--gitleaks-sandbox", action="store_true", help="Run Gitleaks in the WSL sandbox")
    workflow_scan.add_argument("--trivy-sandbox", action="store_true", help="Run Trivy in the WSL sandbox")
    workflow_scan.add_argument("--checkov-mcp", action="store_true", help="Run Checkov IaC audit via isolated HexStrike MCP")
    workflow_scan.add_argument("--semgrep-sarif", type=Path, help="Import an external SARIF report")
    workflow_scan.add_argument("--bandit-json", type=Path, help="Import an external Bandit JSON report")
    workflow_scan.add_argument("--agent-plan", action="store_true", help="Let the model choose only explicitly enabled analyzers")
    workflow_scan.add_argument("--knowledge-context", action="store_true", help="Save a hybrid-retrieval context manifest (PostgreSQL)")
    workflow_scan.add_argument("--staged-knowledge", action="store_true", help="Run knowledge context as a separate durable stage")
    workflow_scan.add_argument("--agent-knowledge", action="store_true", help="Send selected knowledge for advisory guidance; requires --agent-review")
    workflow_scan.add_argument("--agent-review", action="store_true", help="Send limited finding metadata for advisory model review")
    workflow_scan.add_argument("--agent-model", default=None, help="DeepSeek model used for advisory review")
    workflow_scan.add_argument("--reconcile", action="store_true", help="Only reconcile an already committed scan; never execute tools")
    workflow_run = subparsers.add_parser("workflow-run", parents=[workflow_scan], add_help=False,
                                         help="Run/resume the complete journaled multi-agent graph")
    workflow_run.add_argument("--agent-analysis", action="store_true", help="Enable the advisory repository analyst")
    workflow_run.add_argument("--agent-report", action="store_true", help="Enable the advisory report writer")
    workflow_run.add_argument("--pause-after", choices=("initialize", "plan", "analyze", "evidence", "knowledge",
                                                       "analyst", "triage", "writer", "report", "memory"))
    recovery = subparsers.add_parser("workflow-recover", help="Resolve an interrupted stage after inspecting its audit")
    recovery.add_argument("--workflow-id", required=True)
    recovery.add_argument("--stage", required=True)
    recovery.add_argument("--action", required=True, choices=("retry", "abort"))
    recovery.add_argument("--reason", required=True)
    recovery.add_argument("--actor", default="cli")
    recovery.add_argument("--acknowledge-possible-repeat", action="store_true")
    workflow_status = subparsers.add_parser("workflow-status", help="Inspect a workflow operation without retrying it")
    workflow_status.add_argument("--workflow-id", required=True)
    workflow_context = subparsers.add_parser("workflow-context", help="Read verified historical workflow knowledge references")
    workflow_context.add_argument("--workflow-id", required=True)
    web_analyze = subparsers.add_parser(
        "web-analyze", help="Analyze captured web responses offline and store a report")
    web_analyze.add_argument("--snapshot", required=True, type=Path,
                             help="JSON snapshot of previously captured responses")
    web_analyze.add_argument("--project-id", required=True, help="Existing project UUID")
    web_analyze.add_argument("--scope-file", required=True, type=Path,
                             help="JSON Authorization document; do not include credentials")
    web_analyze.add_argument("--actor", default="cli")
    web_analyze.add_argument("--report-format", choices=("markdown", "json"), default="markdown")
    web_analyze.add_argument("--agent-review", action="store_true",
                             help="Ask the DeepSeek triage reviewer for advisory (unverified) opinions")
    web_analyze.add_argument("--agent-model", default=None, help="Override the DeepSeek model")
    web_analyze.add_argument("--validation-requests", action="store_true",
                             help="Queue pending validation approvals for groups that need review")
    fetch = subparsers.add_parser("fetch", help="One allowlisted HTTP GET in a private WSL network namespace")
    fetch.add_argument("--url", required=True, help="Authorized absolute http(s) URL")
    fetch.add_argument("--scope-file", required=True, type=Path, help="JSON Authorization document")
    fetch.add_argument("--actor", default="cli")
    fetch.add_argument("--max-bytes", type=int, default=200_000)
    fetch.add_argument("--operation-id", help="Stable UUID used to resume without repeating completed requests")
    knowledge = subparsers.add_parser("knowledge", help="Knowledge base operations")
    knowledge_sub = knowledge.add_subparsers(dest="knowledge_command", required=True)
    knowledge_ingest = knowledge_sub.add_parser("ingest", help="Chunk and store a local text file")
    knowledge_ingest.add_argument("--file", required=True, type=Path, help="UTF-8 text file to ingest")
    knowledge_ingest.add_argument("--title", required=True, help="Document title")
    knowledge_ingest.add_argument("--source-type", required=True, help="Source type, e.g. CWE/OWASP/note")
    knowledge_ingest.add_argument("--source-url", help="Original source URL, if any")
    knowledge_ingest.add_argument("--version", help="Document version label")
    knowledge_ingest.add_argument("--trust-level", help="Declared trust level")
    knowledge_ingest.add_argument("--size", type=int, default=1000, help="Chunk size in characters")
    knowledge_ingest.add_argument("--overlap", type=int, default=100, help="Chunk overlap in characters")
    workflow_run.add_argument('--skills', type=Path, help='Snapshot selected skill bodies into model context')
    workflow_run.add_argument('--use-memory', action='store_true', help='Use validated project long-term memory')
    attest_parser = subparsers.add_parser('finding-attest', help='Record an evidence-bound local-owner verification decision')
    attest_parser.add_argument('--attestation-id', required=True)
    attest_parser.add_argument('--scan-id', required=True)
    attest_parser.add_argument('--fingerprint', required=True)
    attest_parser.add_argument('--evidence-id', action='append', required=True)
    attest_parser.add_argument('--verdict', required=True, choices=('confirmed','not_reproduced'))
    attest_parser.add_argument('--reason', required=True)
    attest_parser.add_argument('--actor', required=True)
    memory_promote = subparsers.add_parser('memory-promote', help='Explicitly validate and promote a project memory')
    memory_promote.add_argument('--source-id', required=True)
    memory_promote.add_argument('--content', required=True)
    memory_promote.add_argument('--actor', required=True)
    web_loop = subparsers.add_parser('workflow-web', help='Resume discovery, per-round approvals, validation and reports')
    web_loop.add_argument('--workflow-id', required=True)
    web_loop.add_argument('--project-id', required=True)
    web_loop.add_argument('--start', required=True)
    web_loop.add_argument('--scope-file', required=True, type=Path)
    web_loop.add_argument('--rounds', type=int, default=1, choices=(1, 2, 3))
    web_loop.add_argument('--max-pages', type=int, default=10)
    web_loop.add_argument('--max-bytes', type=int, default=200000)
    web_loop.add_argument('--agent-plan', action='store_true')
    web_loop.add_argument('--external-tools', action='store_true', help='Execute approved validation probes via HexStrike MCP')
    web_loop.add_argument('--actor', default='cli')
    args = parser.parse_args()
    if args.command == 'finding-attest':
        from vulnmind.durable_cli import run_attestation
        return run_attestation(args)
    if args.command == 'memory-promote':
        from vulnmind.durable_cli import promote_memory
        return promote_memory(args)
    if args.command == 'workflow-web':
        from vulnmind.durable_cli import run_web
        return run_web(args)
    if args.command == "workflow-run":
        from vulnmind.durable_cli import run_repository
        return run_repository(args)
    if args.command == "workflow-recover":
        from vulnmind.durable_cli import recover
        return recover(args)
    if args.command in {"fetch", "crawl", "validate-run"}:
        from vulnmind.analysis.durable_http import run_command
        return run_command(args)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "report":
        return _show_report(args)
    if args.command == "project-create":
        return _project_create(args)
    if args.command == "approvals":
        return _approvals(args)
    if args.command == "ui":
        from vulnmind.workbench.server import serve
        serve(args.port)
        return 0
    if args.command == "scans":
        return _scans(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "findings":
        return _findings(args)
    if args.command == "finding-feedback":
        return _finding_feedback(args)
    if args.command == "feedback":
        return _feedback_list(args)
    if args.command == "report-regenerate":
        return _report_regenerate(args)
    if args.command == "report-sign":
        return _report_sign(args)
    if args.command == "report-verify":
        return _report_verify(args)
    if args.command == "evidence":
        return _evidence_list(args)
    if args.command == "fetch":
        return _fetch(args)
    if args.command == "evidence-gc":
        return _evidence_gc(args)
    if args.command == "audit-verify":
        return _audit_verify(args)
    if args.command == "audit-trace":
        return _audit_trace(args)
    if args.command == "audit-recent":
        return _audit_recent(args)
    if args.command == "doctor":
        return _doctor(args)
    if args.command == "crawl":
        return _crawl(args)
    if args.command == "endpoints":
        return _endpoints(args)
    if args.command == "shell-request":
        return _shell_request(args)
    if args.command == "shell-run":
        return _shell_run(args)
    if args.command == "validate-request":
        return _validate_request(args)
    if args.command == "validate-run":
        return _validate_run(args)
    if args.command == "validation-plan":
        return _validation_plan(args)
    if args.command == "agent-run":
        return _agent_run(args)
    if args.command == "knowledge-ask":
        return _knowledge_ask(args)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "workflow-scan":
        return _workflow_scan(args)
    if args.command == "workflow-status":
        return _workflow_status(args)
    if args.command == "workflow-context":
        return _workflow_context(args)
    if args.command == "web-analyze":
        return _web_analyze(args)
    if args.command == "knowledge":
        return _knowledge(args)
    try:
        request = ScanRequest.model_validate_json(_read_bounded(args.request, _MAX_REQUEST_BYTES))
        state = {"task_id": request.task_id, "project_id": request.project_id,
                 "targets": [target.model_dump(mode="json") for target in request.targets],
                 "authorized_scope": request.authorization.model_dump(mode="json")}
        audit = _EphemeralAudit()
        result = asyncio.run(build_mock_graph(audit).ainvoke(state))
        # Deliberately do not echo targets, scope, input data or exception details.
        print(json.dumps({"status": result["status"], "report": result.get("report", {}),
                          "errors": result.get("errors", []), "audit": {"persistent": False, "event_count": audit.count}}, ensure_ascii=False))
        return 0 if result["status"] == "simulated" else 2
    except (OSError, UnicodeError, ValueError):
        print(json.dumps({"status": "blocked", "errors": ["invalid or unreadable request"], "audit": {"persistent": False}}))
        return 2


def _analyze(args) -> int:
    """Parse an existing scanner report; no scanner is executed here."""
    try:
        if bool(args.sarif) == bool(args.gitleaks):
            raise AdapterError("exactly one scanner report is required")
        if args.sarif:
            document = _read_report(args.sarif)
            parsed = parse_sarif(document, target_id=args.target_id)
        else:
            document = _read_report(args.gitleaks)
            parsed = parse_gitleaks(document, target_id=args.target_id)
        groups = group_findings(parsed.findings)
        decisions = triage_groups(groups)
        report = generate(ReportInput(scan_id=args.scan_id, project_id=args.project_id, mode="analysis",
                                      groups=groups,
                                      decisions=[DecisionSummary(fingerprint=item.fingerprint,
                                                                 severity=item.severity,
                                                                 confidence=item.confidence,
                                                                 requires_validation=item.requires_validation,
                                                                 rationale=item.rationale)
                                                 for item in decisions],
                                      limitations=["输入为扫描器已有输出；本命令未执行任何扫描",
                                                   "未确认的发现仍需人工验证"] +
                                                  ([f"扫描器有 {parsed.skipped} 条结果无法导入，报告可能不完整"]
                                                   if parsed.skipped else []) +
                                                  (["扫描器输出超过结果上限，报告不完整"] if parsed.truncated else [])),
                          format=args.format)
    except (OSError, UnicodeError, AdapterError, ValueError):
        print(json.dumps({"status": "blocked", "errors": ["invalid or unreadable scanner report"]}, ensure_ascii=False))
        return 2
    if args.output:
        try:
            args.output.write_text(report.content, encoding="utf-8")
        except OSError:
            print(json.dumps({"status": "blocked", "errors": ["report could not be written"]}, ensure_ascii=False))
            return 2
        print(json.dumps({"status": "written", "format": report.format, "sha256": report.sha256,
                          "counts": report.counts, "findings": len(parsed.findings),
                          "skipped": parsed.skipped, "truncated": parsed.truncated, "groups": len(groups),
                          "requires_validation": sum(1 for item in decisions if item.requires_validation)},
                         ensure_ascii=False))
        return 0
    print(report.content, end="")
    return 0



def _read_report(path: Path) -> str:
    # Bound the read itself, including when the file grows concurrently.
    from vulnmind.tools.adapters import MAX_DOCUMENT_BYTES
    with path.open("rb") as source:
        data = source.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise AdapterError("scanner report exceeds size limit")
    return data.decode("utf-8")


def _findings(args) -> int:
    """List stored findings for one scan; read-only."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Finding, Scan

    settings = Settings()
    try:
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        if isinstance(args.limit, bool) or not 1 <= args.limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                rows = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)
                                            .order_by(Finding.vuln_type, Finding.fingerprint)
                                            .limit(args.limit)))
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["finding listing failed"]}, ensure_ascii=False))
        return 2
    payload = [{"id": str(row.id), "fingerprint": row.fingerprint, "title": row.title,
                "vuln_type": row.vuln_type, "severity": row.severity, "confidence": row.confidence,
                "status": row.status, "location": row.location} for row in rows]
    print(json.dumps({"status": "listed", "scan_id": str(scan_id), "findings": payload},
                     ensure_ascii=False))
    return 0


def _audit_target_type(session, project_id) -> str:
    """Best-effort audit label for a scan's project; never raises."""
    from sqlalchemy import select

    from vulnmind.persistence.models import TargetRecord

    try:
        value = session.scalars(select(TargetRecord.target_type)
                                .where(TargetRecord.project_id == project_id)
                                .order_by(TargetRecord.id).limit(1)).first()
    except Exception:  # noqa: BLE001 - an audit label must not block the decision
        return "repository"
    return "web" if isinstance(value, str) and value.strip().lower() == "web" else "repository"


def _finding_feedback(args) -> int:
    """Record one operator verdict; it is a decision, not a verification result."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.models import Scan
    from vulnmind.persistence.repositories import FeedbackRepository

    scan_id = None
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ValueError("scan is not stored")
                audit = SessionAuditSink(session)
                event = {"call_id": str(uuid4()), "tool_name": "finding.feedback",
                         "actor": args.actor,
                         "target_type": _audit_target_type(session, scan.project_id)}
                audit.record({**event, "status": "requested"})
                row = FeedbackRepository(session).record(scan_id, args.fingerprint, args.verdict,
                                                         actor=args.actor, note=args.note)
                revision, verdict, note_present = row.revision, row.verdict, bool(row.note)
                audit.record({**event, "status": "pending_commit"})
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message, no note/actor echo
        print(json.dumps({"status": "blocked", "errors": ["feedback could not be recorded"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "recorded", "scan_id": str(scan_id),
                      "fingerprint": args.fingerprint, "verdict": verdict,
                      "revision": revision, "note_present": note_present},
                     ensure_ascii=False))
    return 0


def _feedback_list(args) -> int:
    """List the newest verdict per finding; read-only."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Scan
    from vulnmind.persistence.repositories import FeedbackRepository

    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        if isinstance(args.limit, bool) or not 1 <= args.limit <= 2000:
            raise ValueError("invalid limit")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                latest = FeedbackRepository(session).latest_for_scan(scan_id, limit=args.limit)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["feedback listing failed"]},
                         ensure_ascii=False))
        return 2
    payload = [{"fingerprint": fingerprint, "verdict": row.verdict, "revision": row.revision,
                "actor": row.actor, "note": row.note,
                "recorded_at": row.created_at.isoformat() if row.created_at is not None else None}
               for fingerprint, row in sorted(latest.items())]
    print(json.dumps({"status": "listed", "scan_id": str(scan_id), "count": len(payload),
                      "feedback": payload}, ensure_ascii=False))
    return 0


def _report_regenerate(args) -> int:
    """Rebuild a report from stored findings and the newest operator verdicts."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.models import Scan
    from vulnmind.reports.regenerate import ReportRegenerator
    from vulnmind.reports.store import ReportStore

    scan_id = None
    try:
        settings = Settings()
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ValueError("scan is not stored")
                audit = SessionAuditSink(session)
                event = {"call_id": str(uuid4()), "tool_name": "report.regenerate",
                         "actor": args.actor,
                         "target_type": _audit_target_type(session, scan.project_id)}
                audit.record({**event, "status": "requested"})
                result = ReportRegenerator(session, ReportStore(Path(settings.report_root))).regenerate(
                    scan_id, report_format=args.report_format, actor=args.actor)
                audit.record({**event, "status": "pending_commit"})
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["report could not be regenerated"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "regenerated", "scan_id": str(scan_id),
                      "format": result.report.format, "sha256": result.report.sha256,
                      "uri": result.reference.uri, "groups": result.groups,
                      "feedback_applied": result.feedback_applied,
                      "evidence_ids": result.evidence_ids,
                      "validation_required": sum(1 for item in result.decisions
                                                 if item.requires_validation)},
                     ensure_ascii=False))
    return 0


def _signing_key(settings):
    from vulnmind.reports.signing import SigningError, resolve_signing_key

    if not settings.report_signing_key and not settings.report_signing_key_file:
        raise SigningError("no report signing key is configured")
    return resolve_signing_key(key=settings.report_signing_key,
                               key_file=settings.report_signing_key_file)


def _report_sign(args) -> int:
    """Sign the newest stored report; never prints or stores the key."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.models import Scan
    from vulnmind.reports.loader import load_report
    from vulnmind.reports.signing import sign_bytes, signature_json
    from vulnmind.reports.store import ReportStore

    scan_id = None
    try:
        settings = Settings()
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        key, key_id = _signing_key(settings)
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                scan = session.get(Scan, scan_id)
                if scan is None:
                    raise ValueError("scan is not stored")
                store = ReportStore(Path(settings.report_root))
                loaded = load_report(session, store, scan_id)
                if loaded.content is None or loaded.storage_uri is None:
                    raise ValueError("report is missing")
                record = sign_bytes(loaded.content.encode("utf-8"), key=key, key_id=key_id)
                audit = SessionAuditSink(session)
                event = {"call_id": str(uuid4()), "tool_name": "report.sign", "actor": args.actor,
                         "target_type": _audit_target_type(session, scan.project_id)}
                audit.record({**event, "status": "requested"})
                signature_uri = store.put_signature(loaded.storage_uri, signature_json(record))
                audit.record({**event, "status": "pending_commit"})
                report_format, digest = loaded.format, record.sha256
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message, no key or path echo
        print(json.dumps({"status": "blocked", "errors": ["report could not be signed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "signed", "scan_id": str(scan_id), "format": report_format,
                      "sha256": digest, "key_id": record.key_id,
                      "signature_uri": signature_uri}, ensure_ascii=False))
    return 0


def _report_verify(args) -> int:
    """Verify the newest stored report signature; no content is printed."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Scan
    from vulnmind.reports.loader import load_report
    from vulnmind.reports.signing import SigningError, verify_bytes
    from vulnmind.reports.store import ReportStore, ReportStoreError

    try:
        settings = Settings()
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        key, _ = _signing_key(settings)
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                store = ReportStore(Path(settings.report_root))
                loaded = load_report(session, store, scan_id)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["report could not be verified"]},
                         ensure_ascii=False))
        return 2
    if loaded.content is None or loaded.storage_uri is None:
        print(json.dumps({"status": "missing", "scan_id": str(scan_id)}, ensure_ascii=False))
        return 1
    try:
        stored = store.read_signature(loaded.storage_uri)
    except ReportStoreError:
        print(json.dumps({"status": "broken", "scan_id": str(scan_id),
                          "reason": "signature_unreadable"}, ensure_ascii=False))
        return 1
    if stored is None:
        print(json.dumps({"status": "unsigned", "scan_id": str(scan_id)}, ensure_ascii=False))
        return 1
    try:
        record = verify_bytes(loaded.content.encode("utf-8"), stored, key=key)
    except SigningError:
        print(json.dumps({"status": "broken", "scan_id": str(scan_id),
                          "reason": "signature_does_not_verify"}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "verified", "scan_id": str(scan_id), "format": loaded.format,
                      "sha256": record.sha256, "key_id": record.key_id}, ensure_ascii=False))
    return 0


def _web_analyze(args) -> int:
    """Analyze a captured web snapshot; this command performs no network access."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.web_orchestrator import WebScanOrchestrator, WebScanRunRequest
    from vulnmind.analysis.web_service import MAX_SNAPSHOT_BYTES, parse_snapshot
    from vulnmind.config import Settings
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.persistence.scan_audit import ScanCommitUnknown, repository_scan_transaction
    from vulnmind.persistence.models import Project
    from vulnmind.reports.store import ReportStore
    from vulnmind.schemas import Authorization

    settings = Settings()
    try:
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        authorization = Authorization.model_validate_json(
            _read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        with args.snapshot.open("rb") as handle:
            data = handle.read(MAX_SNAPSHOT_BYTES + 1)
        snapshot = parse_snapshot(data)
        project_id = UUID(args.project_id)
        agent_client = None
        if args.agent_review:
            from vulnmind.agents.deepseek import DeepSeekClient
            agent_client = DeepSeekClient(model=args.agent_model) if args.agent_model else DeepSeekClient()
        engine = create_engine(settings.database_url)
        try:
            with repository_scan_transaction(engine, actor=args.actor, target_type="web") as (session, audit, audit_call_id):
                if session.get(Project, project_id) is None:
                    raise ValueError("project is not stored")
                agent_runtime = None
                if agent_client is not None:
                    from vulnmind.agents.audit import AgentAuditBridge
                    from vulnmind.agents.runtime import AgentRuntime
                    agent_runtime = AgentRuntime(agent_client,
                                                 AgentAuditBridge(audit, target_type="web"))
                evidence_store = (EvidenceStore(Path(settings.evidence_root))
                                  if settings.evidence_root else None)
                approvals = None
                if args.validation_requests:
                    from vulnmind.security.approvals import ApprovalService
                    approvals = ApprovalService(session)
                orchestrator = WebScanOrchestrator(
                    session, audit, ReportStore(Path(settings.report_root)),
                    evidence_store=evidence_store, approvals=approvals,
                    agent_runtime=agent_runtime)
                outcome = orchestrator.run(WebScanRunRequest(
                    project_id=project_id, actor=args.actor, target=snapshot.target,
                    scope=authorization, snapshot=snapshot, report_format=args.report_format))
        finally:
            engine.dispose()
    except ScanCommitUnknown:
        pending_outcome = locals().get("outcome")
        print(json.dumps({"status": "unknown", "scan_id": str(pending_outcome.scan_id) if pending_outcome else None,
                          "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["scan audit or commit is uncertain; inspect stored records before retrying"]}))
        return 2
    except Exception:  # noqa: BLE001 - fixed message, no snapshot or scope details
        print(json.dumps({"status": "blocked", "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["web analysis could not be completed"]},
                         ensure_ascii=False))
        return 2
    analysis = outcome.analysis
    print(json.dumps({"status": outcome.status, "scan_id": str(outcome.scan_id),
                      "pages_analyzed": analysis.pages_analyzed,
                      "pages_skipped": analysis.pages_skipped,
                      "out_of_scope": analysis.out_of_scope,
                      "endpoints": len(analysis.endpoints),
                      "groups": len(analysis.groups),
                      "findings_stored": len(outcome.stored.stored),
                      "evidence_stored": outcome.evidence_stored,
                      "validation_requests": outcome.validation_requests,
                      "report": outcome.report.uri, "report_sha256": outcome.report.sha256,
                      "agent_review_status": outcome.agent_review_status,
                      "audit_call_id": audit_call_id,
                      "audit_independent": engine.dialect.name == "postgresql",
                      "agent_verdicts": outcome.agent_verdicts}, ensure_ascii=False))
    return 0


def _project_create(args) -> int:
    """Create a project and its audit event in the same database transaction."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.models import Project

    project_id = uuid4()
    committing = False
    try:
        if (not args.name.strip() or len(args.name) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in args.name)):
            raise ValueError("invalid project name")
        database_url = Settings().database_url
        if not database_url:
            raise ValueError("database is not configured")
        engine = create_engine(database_url)
        try:
            with Session(engine) as session:
                session.add(Project(id=project_id, name=args.name))
                session.flush()
                SessionAuditSink(session).record({"call_id": str(project_id),
                    "tool_name": "project.create", "actor": args.actor,
                    "target_type": "repository", "status": "pending_commit"})
                committing = True
                session.commit()
        finally:
            engine.dispose()
    except Exception:
        if committing:
            print(json.dumps({"status": "unknown", "project_id": str(project_id),
                              "errors": ["commit could not be confirmed; inspect the project before retrying"]}))
        else:
            print(json.dumps({"status": "blocked", "errors": ["project could not be created"]}))
        return 2
    print(json.dumps({"status": "created", "project_id": str(project_id)}))
    return 0


def _workflow_scan(args) -> int:
    """Opt-in single-attempt repository workflow with explicitly enabled tools."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
    from vulnmind.analysis.python_tls import find_python_tls_candidates
    from vulnmind.config import Settings
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.graph.guarded_repository_workflow import build_guarded_repository_graph
    from vulnmind.persistence.models import Project, Scan
    from vulnmind.persistence.scan_audit import repository_scan_transaction
    from vulnmind.reports.store import ReportStore
    from vulnmind.schemas import Authorization, Target
    import hashlib

    graph_invoked = False
    try:
        workflow_id, project_id = UUID(args.workflow_id), UUID(args.project_id)
        if (not args.actor.strip() or len(args.actor) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in args.actor)):
            raise ValueError("invalid actor")
        settings = Settings()
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root are required")
        enabled_tools = {name for name, enabled in (
            ("gitleaks_sandbox", args.gitleaks_sandbox), ("trivy_sandbox", args.trivy_sandbox),
            ("semgrep_sarif", args.semgrep_sarif is not None), ("bandit_json", args.bandit_json is not None)) if enabled}
        if args.agent_plan and not enabled_tools:
            raise ValueError("agent planning requires at least one optional scanner")
        if args.agent_knowledge and not args.agent_review:
            raise ValueError("knowledge guidance requires advisory review")
        if args.staged_knowledge and not args.knowledge_context:
            raise ValueError("staged knowledge requires knowledge context")
        if args.agent_model and not (args.agent_review or args.agent_plan):
            raise ValueError("agent model requires planning or advisory review")
        agent_client = None
        if args.agent_review or args.agent_plan:
            from vulnmind.agents.deepseek import DEFAULT_MODEL, DeepSeekClient
            if args.agent_review and not args.reconcile:
                agent_client = DeepSeekClient(model=args.agent_model or DEFAULT_MODEL)
        target = Target(type="repository", locator=str(args.repository.resolve()))
        scope = Authorization.model_validate_json(_read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        from vulnmind.analysis.repo_analyzers import MAX_REPORT_BYTES
        reports = {}
        for name, supplied in (("semgrep_sarif", args.semgrep_sarif), ("bandit_json", args.bandit_json)):
            if supplied is not None:
                path = supplied.resolve(strict=True)
                if not path.is_file():
                    raise ValueError("scanner report must be a file")
                with path.open("rb") as stream:
                    data = stream.read(MAX_REPORT_BYTES + 1)
                if len(data) > MAX_REPORT_BYTES:
                    raise ValueError("scanner report is too large")
                reports[name] = {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
        report_root = Path(settings.report_root).resolve()
        evidence_root = Path(settings.evidence_root).resolve() if settings.evidence_root else None
        engine = create_engine(settings.database_url)
        try:
            if (args.knowledge_context or args.agent_knowledge) and engine.dialect.name != "postgresql":
                raise ValueError("knowledge retrieval requires PostgreSQL")
            with Session(engine) as session:
                if session.get(Project, project_id) is None:
                    raise ValueError("project is unavailable")
            state = {"task_id": str(workflow_id), "project_id": str(project_id),
                     "targets": [target.model_dump(mode="json")],
                     "authorized_scope": scope.model_dump(mode="json"),
                     "workflow_options": {"version": 1, "tools": ["python_tls", *sorted(enabled_tools)], "actor": args.actor,
                        "report_format": args.report_format, "report_root": str(report_root),
                        "evidence_root": str(evidence_root) if evidence_root else None,
                        "agent_review": args.agent_review,
                        "agent_model": (args.agent_model or DEFAULT_MODEL) if (args.agent_review or args.agent_plan) else None}}
            if args.agent_plan:
                state["workflow_options"]["agent_plan"] = True
            if args.knowledge_context:
                state["workflow_options"]["knowledge_context"] = True
            if args.staged_knowledge:
                state["workflow_options"]["staged_knowledge"] = True
            if args.agent_knowledge:
                state["workflow_options"]["agent_knowledge"] = True
            if reports:
                state["workflow_options"]["reports"] = reports

            def prepare_plan(current):
                nonlocal agent_client
                from sqlalchemy import select
                from vulnmind.persistence.models import WorkflowToolPlan
                # Check the required schema before claiming or contacting a
                # model, so a missing migration cannot consume an attempt.
                with Session(engine) as session:
                    session.execute(select(WorkflowToolPlan).limit(0))
                if agent_client is None:
                    agent_client = DeepSeekClient(model=args.agent_model or DEFAULT_MODEL)

            def plan(current, operation_id, owner_token, input_digest, enabled):
                from vulnmind.persistence.workflow_plans import execute_tool_plan
                return execute_tool_plan(engine, operation_id=operation_id, owner_token=owner_token,
                                         input_digest=input_digest, enabled=enabled, actor=args.actor, client=agent_client)

            def execute(current):
                operation_id = UUID(current["workflow_operation_id"])
                with repository_scan_transaction(engine, actor=args.actor, call_id=operation_id) as (session, audit, _):
                    runtime = None
                    if agent_client is not None:
                        from vulnmind.agents.audit import AgentAuditBridge
                        from vulnmind.agents.runtime import AgentRuntime
                        runtime = AgentRuntime(agent_client, AgentAuditBridge(audit, target_type="repository"))
                    selected_tools = enabled_tools
                    if args.agent_plan:
                        selection = current.get("plan", {}).get("selected_tools")
                        if (not isinstance(selection, list) or any(not isinstance(item, str) for item in selection)
                                or len(selection) != len(set(selection)) or not set(selection) <= enabled_tools):
                            raise ValueError("stored planner selection is invalid")
                        selected_tools = set(selection)
                    repo_analyzers = []
                    if "gitleaks_sandbox" in selected_tools:
                        from vulnmind.analysis.repo_analyzers import SandboxedGitleaksAnalyzer
                        from vulnmind.analysis.sandbox import WslSandbox
                        repo_analyzers.append(SandboxedGitleaksAnalyzer(WslSandbox(), target_id="repository"))
                    if "trivy_sandbox" in selected_tools:
                        from vulnmind.analysis.repo_analyzers import SandboxedTrivyAnalyzer
                        from vulnmind.analysis.sandbox import WslSandbox
                        repo_analyzers.append(SandboxedTrivyAnalyzer(WslSandbox(), target_id="repository"))
                    if "semgrep_sarif" in selected_tools:
                        from vulnmind.analysis.repo_analyzers import SarifReportAnalyzer
                        item = reports["semgrep_sarif"]
                        repo_analyzers.append(SarifReportAnalyzer(Path(item["path"]), target_id="repository",
                                                                  expected_sha256=item["sha256"]))
                    if "bandit_json" in selected_tools:
                        from vulnmind.analysis.bandit import BanditReportAnalyzer
                        item = reports["bandit_json"]
                        repo_analyzers.append(BanditReportAnalyzer(Path(item["path"]), target_id="repository",
                                                                   expected_sha256=item["sha256"]))
                    omitted_tools = sorted(enabled_tools - selected_tools)
                    provider = None
                    knowledge_advisor = None
                    if (args.knowledge_context and not args.staged_knowledge) or args.agent_knowledge:
                        from vulnmind.knowledge.hybrid import LocalQueryEncoder, PostgresHybridRetriever
                        from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
                        hybrid = PostgresHybridRetriever(session, encoder=LocalQueryEncoder())
                        if args.knowledge_context and not args.staged_knowledge:
                            from vulnmind.context.scan_manifest import knowledge_manifest_provider
                            provider = knowledge_manifest_provider(hybrid, DatabaseChunkStore(session),
                                                                   retrieval_method="hybrid")
                        if args.agent_knowledge:
                            from vulnmind.context.scan_knowledge import scan_knowledge_advisor
                            knowledge_advisor = scan_knowledge_advisor(hybrid, DatabaseChunkStore(session), runtime)
                    service = ScanOrchestrator(session, audit, [find_python_tls_candidates], ReportStore(report_root),
                                               evidence_store=EvidenceStore(evidence_root) if evidence_root else None,
                                               manifest_provider=provider, knowledge_advisor=knowledge_advisor,
                                               repo_analyzers=repo_analyzers,
                                               agent_runtime=runtime if args.agent_review else None,
                                               additional_limitations=(
                                                   (["模型规划仅从用户启用的分析器中选择，不构成漏洞验证"]
                                                    if args.agent_plan else [])
                                                   + [f"模型规划未选择用户启用的分析器: {name}"
                                                      for name in omitted_tools]))
                    result = service.run(ScanRunRequest(project_id=project_id, actor=args.actor, target=target,
                                                       scope=scope, report_format=args.report_format),
                                         scan_id=operation_id)
                    scan_id = result.scan_id
                return scan_id

            def reconcile(workflow, operation, digest, current):
                from vulnmind.persistence.workflow_reconcile import reconcile_repository_scan
                if args.agent_plan:
                    from vulnmind.persistence.workflow_operations import lookup_stage
                    from vulnmind.persistence.workflow_plans import load_tool_plan
                    saved_plan = lookup_stage(engine, workflow_id=workflow, stage="repository_plan", input_digest=digest)
                    # Older committed workflows predate the independent plan
                    # stage. When a plan exists, require its verified receipt.
                    if saved_plan is not None:
                        if saved_plan.status != "completed":
                            return False
                        load_tool_plan(engine, plan_id=saved_plan.result_id, operation_id=saved_plan.operation_id,
                                       enabled=enabled_tools)
                return reconcile_repository_scan(engine, workflow_id=workflow, operation_id=operation,
                    input_digest=digest, project_id=project_id, report_root=report_root, actor=args.actor)

            def verify_report(current, scan_id):
                from vulnmind.reports.identity import matches_scan
                from vulnmind.reports.loader import load_report
                if scan_id != UUID(current["report"]["operation_id"]):
                    return False
                if not report_root.is_dir():
                    return False
                with Session(engine) as session:
                    stored = session.get(Scan, scan_id)
                    if stored is None or stored.project_id != project_id or stored.status != "finished":
                        return False
                    loaded = load_report(session, ReportStore(report_root), scan_id)
                    return (loaded.content is not None and matches_scan(loaded.content, loaded.format,
                                                                         scan_id=scan_id, project_id=project_id))

            staged_encoder = None
            def prepare_knowledge(current):
                nonlocal staged_encoder
                from vulnmind.knowledge.hybrid import LocalQueryEncoder
                staged_encoder = LocalQueryEncoder()

            def execute_knowledge(current, operation_id, owner_token, digest, scan_id):
                from vulnmind.persistence.workflow_knowledge import save_knowledge_stage
                return save_knowledge_stage(engine, operation_id=operation_id, owner_token=owner_token,
                    input_digest=digest, scan_id=scan_id, project_id=project_id, target_id=target.locator,
                    actor=args.actor, encoder=staged_encoder)

            def verify_knowledge(current, operation_id, manifest_id, digest, scan_id):
                from vulnmind.persistence.workflow_knowledge import verify_knowledge_stage
                return verify_knowledge_stage(engine, operation_id=operation_id, manifest_id=manifest_id,
                    input_digest=digest, scan_id=scan_id, project_id=project_id)

            graph = build_guarded_repository_graph(engine, execute, reconcile_only=args.reconcile,
                                                   reconciler=reconcile if args.reconcile else None,
                                                   plan_executor=plan if args.agent_plan else None,
                                                   plan_prepare=prepare_plan if args.agent_plan else None,
                                                   report_verifier=verify_report,
                                                   knowledge_executor=execute_knowledge if args.staged_knowledge else None,
                                                   knowledge_prepare=prepare_knowledge if args.staged_knowledge else None,
                                                   knowledge_verifier=verify_knowledge if args.staged_knowledge else None)
            graph_invoked = True
            result = graph.invoke(state)
        finally:
            engine.dispose()
    except Exception:
        if graph_invoked:
            print(json.dumps({"status": "unknown", "workflow_id": str(workflow_id),
                              "errors": ["workflow outcome could not be confirmed"]}))
        else:
            print(json.dumps({"status": "blocked", "errors": ["workflow could not be started"]}))
        return 2
    payload = {"status": result["status"], "workflow_id": str(workflow_id),
               "scan_id": result.get("report", {}).get("scan_id"), "errors": result.get("errors", [])}
    print(json.dumps(payload))
    return 0 if result["status"] == "finished" else 2


def _workflow_status(args) -> int:
    """Report durable claims without exposing tokens, request digests or targets."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from vulnmind.config import Settings
    from vulnmind.persistence.models import WorkflowOperation

    try:
        workflow_id = UUID(args.workflow_id)
        url = Settings().database_url
        if not url:
            raise ValueError("database is required")
        engine = create_engine(url)
        try:
            with Session(engine) as session:
                rows = session.scalars(select(WorkflowOperation).where(
                    WorkflowOperation.workflow_id == workflow_id).order_by(WorkflowOperation.stage)).all()
                operations = [{"stage": row.stage, "operation_id": str(row.id),
                               "status": "unknown" if row.status == "started" else row.status,
                               "result_id": row.result_ref} for row in rows]
                from sqlalchemy import inspect
                from vulnmind.persistence.models import DurableStep
                if inspect(engine).has_table("durable_steps"):
                    stages = session.scalars(select(DurableStep).where(
                        DurableStep.workflow_id == workflow_id).order_by(DurableStep.created_at, DurableStep.stage)).all()
                    operations.extend({"stage": row.stage, "operation_id": str(row.id),
                        "status": "unknown" if row.status == "running" else row.status,
                        "attempt": row.attempt, "engine": "durable_v2"} for row in stages)
        finally:
            engine.dispose()
    except Exception:
        print(json.dumps({"status": "blocked", "errors": ["workflow status is unavailable"]}))
        return 2
    print(json.dumps({"status": "found" if operations else "not_found", "workflow_id": str(workflow_id),
                      "operations": operations}))
    return 0


def _workflow_context(args) -> int:
    """Read references, not retrieved knowledge bodies or external URLs."""
    from sqlalchemy import create_engine
    from vulnmind.config import Settings
    from vulnmind.persistence.workflow_knowledge import read_workflow_context

    try:
        workflow_id = UUID(args.workflow_id)
        url = Settings().database_url
        if not url:
            raise ValueError("database is required")
        engine = create_engine(url)
        try:
            payload = read_workflow_context(engine, workflow_id)
        finally:
            engine.dispose()
    except Exception:
        print(json.dumps({"status": "blocked", "errors": ["verified workflow context is unavailable"]}))
        return 2
    print(json.dumps({"status": "loaded", **payload}, ensure_ascii=False))
    return 0


def _run_scan(args) -> int:
    """Run the built-in repository analysis with an explicit authorization file."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
    from vulnmind.analysis.python_tls import find_python_tls_candidates
    from vulnmind.config import Settings
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.persistence.scan_audit import ScanCommitUnknown, repository_scan_transaction
    from vulnmind.persistence.models import Project
    from vulnmind.reports.store import ReportStore
    from vulnmind.schemas import Authorization, Target

    settings = Settings()
    try:
        if args.agent_knowledge and not args.agent_review:
            raise ValueError("knowledge review requires explicit agent review")
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        agent_client = None
        if args.agent_review or args.agent_plan:
            from vulnmind.agents.deepseek import DeepSeekClient
            agent_client = DeepSeekClient(model=args.agent_model) if args.agent_model else DeepSeekClient()
        scope_text = _read_bounded(args.scope_file, _MAX_REQUEST_BYTES)
        authorization = Authorization.model_validate_json(scope_text)
        repository = Path(args.repository)
        if not repository.is_absolute():
            repository = repository.resolve()
        project_id = UUID(args.project_id)
        engine = create_engine(settings.database_url)
        try:
            with repository_scan_transaction(engine, actor=args.actor) as (session, audit, audit_call_id):
                if session.get(Project, project_id) is None:
                    raise ValueError("project is not stored")
                enabled_tools = {name for name, enabled in (
                    ("gitleaks_sandbox", args.gitleaks_sandbox), ("trivy_sandbox", args.trivy_sandbox),
                    ("semgrep_sarif", args.semgrep_sarif is not None), ("bandit_json", args.bandit_json is not None))
                    if enabled}
                selected_tools = enabled_tools
                if args.agent_plan:
                    from vulnmind.agents.audit import AgentAuditBridge
                    from vulnmind.agents.runtime import AgentRuntime
                    from vulnmind.agents.tool_plan import select_repository_tools
                    from vulnmind.security.scope import check_target
                    check_target(Target(type="repository", locator=str(repository)), authorization)
                    # Planning precedes the scan's first write. Persist its audit in
                    # separate transactions so a later scan rollback cannot erase it.
                    from vulnmind.persistence.audit import DatabaseAuditSink
                    from vulnmind.persistence.scan_audit import CorrelatedAuditSink
                    planning_audit = (audit if engine.dialect.name == "postgresql" else
                                      CorrelatedAuditSink(DatabaseAuditSink(engine), audit_call_id))
                    planning_runtime = AgentRuntime(agent_client, AgentAuditBridge(planning_audit, target_type="repository"))
                    planning_event = {"call_id": str(uuid4()), "tool_name": "repository.plan.selection",
                                      "actor": args.actor, "target_type": "repository"}
                    planning_audit.record({**planning_event, "status": "requested"})
                    try:
                        selected_tools = set(select_repository_tools(planning_runtime, enabled=enabled_tools, actor=args.actor))
                    except Exception:
                        planning_audit.record({**planning_event, "status": "failed"})
                        raise
                    planning_audit.record({**planning_event, "status": "succeeded"})
                omitted_tools = sorted(enabled_tools - selected_tools)
                provider = None
                hybrid = None
                if args.knowledge_context or args.agent_knowledge:
                    if session.get_bind().dialect.name != "postgresql":
                        raise ValueError("knowledge retrieval requires PostgreSQL")
                    from vulnmind.knowledge.hybrid import LocalQueryEncoder, PostgresHybridRetriever
                    hybrid = PostgresHybridRetriever(session, encoder=LocalQueryEncoder())
                if args.knowledge_context:
                    if session.get_bind().dialect.name != "postgresql":
                        raise ValueError("knowledge context requires PostgreSQL")
                    from vulnmind.context.scan_manifest import knowledge_manifest_provider
                    from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
                    from vulnmind.knowledge.skills import SkillLoader
                    loader = SkillLoader(args.skills) if args.skills is not None else None
                    provider = knowledge_manifest_provider(hybrid, DatabaseChunkStore(session),
                                                           loader=loader, retrieval_method="hybrid")
                elif args.skills is not None:
                    from vulnmind.context.scan_manifest import default_skill_provider
                    provider = default_skill_provider(args.skills)
                repo_analyzers = []
                if args.gitleaks is not None:
                    from vulnmind.analysis.repo_analyzers import GitleaksAnalyzer
                    executable = Path(args.gitleaks).resolve(strict=True)
                    repo_analyzers.append(GitleaksAnalyzer(executable, trusted_root=executable.parent,
                                                           target_id="repository"))
                if "gitleaks_sandbox" in selected_tools:
                    from vulnmind.analysis.repo_analyzers import SandboxedGitleaksAnalyzer
                    from vulnmind.analysis.sandbox import WslSandbox
                    repo_analyzers.append(SandboxedGitleaksAnalyzer(WslSandbox(), target_id="repository"))
                if "trivy_sandbox" in selected_tools:
                    from vulnmind.analysis.repo_analyzers import SandboxedTrivyAnalyzer
                    from vulnmind.analysis.sandbox import WslSandbox
                    repo_analyzers.append(SandboxedTrivyAnalyzer(WslSandbox(), target_id="repository"))
                if "semgrep_sarif" in selected_tools:
                    from vulnmind.analysis.repo_analyzers import SarifReportAnalyzer
                    repo_analyzers.append(SarifReportAnalyzer(args.semgrep_sarif,
                                                              target_id="repository"))
                if "bandit_json" in selected_tools:
                    from vulnmind.analysis.bandit import BanditReportAnalyzer
                    repo_analyzers.append(BanditReportAnalyzer(args.bandit_json, target_id="repository"))
                agent_runtime = None
                if args.agent_review and agent_client is not None:
                    from vulnmind.agents.audit import AgentAuditBridge
                    from vulnmind.agents.runtime import AgentRuntime
                    agent_runtime = AgentRuntime(agent_client,
                                                 AgentAuditBridge(audit, target_type="repository"))
                knowledge_advisor = None
                if args.agent_knowledge:
                    if session.get_bind().dialect.name != "postgresql":
                        raise ValueError("knowledge review requires PostgreSQL")
                    from vulnmind.context.scan_knowledge import scan_knowledge_advisor
                    from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
                    knowledge_advisor = scan_knowledge_advisor(hybrid,
                                                               DatabaseChunkStore(session), agent_runtime)
                orchestrator = ScanOrchestrator(session, audit, [find_python_tls_candidates],
                                                ReportStore(Path(settings.report_root)),
                                                evidence_store=(EvidenceStore(Path(settings.evidence_root))
                                                                if settings.evidence_root else None),
                                                manifest_provider=provider,
                                                repo_analyzers=repo_analyzers,
                                                agent_runtime=agent_runtime,
                                                knowledge_advisor=knowledge_advisor,
                                                additional_limitations=(
                                                    (["模型规划仅从用户启用的分析器中选择，不构成漏洞验证"]
                                                     if args.agent_plan else [])
                                                    + [f"模型规划未选择用户启用的分析器: {name}"
                                                       for name in omitted_tools]))
                outcome = orchestrator.run(ScanRunRequest(
                    project_id=project_id, actor=args.actor,
                    target=Target(type="repository", locator=str(repository)),
                    scope=authorization, report_format=args.report_format))
        finally:
            engine.dispose()
    except ScanCommitUnknown:
        pending_outcome = locals().get("outcome")
        print(json.dumps({"status": "unknown", "scan_id": str(pending_outcome.scan_id) if pending_outcome else None,
                          "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["scan audit or commit is uncertain; inspect stored records before retrying"]}))
        return 2
    except Exception:  # noqa: BLE001 - fixed message, no paths, scope or SQL details
        print(json.dumps({"status": "blocked", "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["scan could not be completed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": outcome.status, "scan_id": str(outcome.scan_id),
                      "files_examined": outcome.files_examined,
                      "files_skipped": outcome.files_skipped,
                      "groups": outcome.groups, "findings_stored": len(outcome.stored.stored),
                      "evidence_stored": outcome.evidence_stored,
                      "context_manifest": str(outcome.context_manifest_id) if outcome.context_manifest_id else None,
                      "agent_review": outcome.agent_review_status,
                      "agent_verdicts": outcome.agent_verdicts,
                      "audit_call_id": audit_call_id,
                      "audit_independent": engine.dialect.name == "postgresql",
                      "planned_tools": sorted(selected_tools) if args.agent_plan else None,
                      "planner_omitted_tools": omitted_tools if args.agent_plan else [],
                      "report_uri": outcome.report.uri, "report_sha256": outcome.report.sha256},
                     ensure_ascii=False))
    return 0


def _evidence_list(args) -> int:
    """List evidence references for one scan; read-only, no bytes are returned."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Evidence, Finding, Scan

    settings = Settings()
    try:
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                finding_ids = select(Finding.id).where(Finding.scan_id == scan_id)
                rows = list(session.scalars(select(Evidence).where(Evidence.finding_id.in_(finding_ids))))
                fingerprints = {row.id: row.fingerprint for row in session.scalars(
                    select(Finding).where(Finding.scan_id == scan_id))}
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["evidence listing failed"]}, ensure_ascii=False))
        return 2
    payload = [{"id": str(row.id), "fingerprint": fingerprints.get(row.finding_id),
                "evidence_type": row.evidence_type, "locator": row.locator,
                "content_ref": row.content_ref, "hash": row.hash} for row in rows]
    print(json.dumps({"status": "listed", "scan_id": str(scan_id), "evidence": payload},
                     ensure_ascii=False))
    return 0


def _knowledge(args) -> int:
    """Ingest a local text file into the knowledge tables; no network, no URL fetch."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.knowledge.ingestion import ingest_document

    settings = Settings()
    try:
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        content = _read_bounded(args.file, 10_000_000)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                ingested = ingest_document(session, title=args.title, content=content,
                                           source_type=args.source_type, source_url=args.source_url,
                                           version=args.version, trust_level=args.trust_level,
                                           size=args.size, overlap=args.overlap)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message, no path or SQL details
        print(json.dumps({"status": "blocked", "errors": ["knowledge ingestion failed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "ingested", "document_id": str(ingested.document_id),
                      "chunks": ingested.chunk_count,
                      "sparse_index": ingested.has_sparse_index}, ensure_ascii=False))
    return 0


def _scans(args) -> int:
    """List scans for a project; read-only."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.repositories import ScanRepository

    settings = Settings()
    try:
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                rows = ScanRepository(session).list_for_project(UUID(args.project_id), limit=args.limit)
                payload = [{"id": str(row.id), "status": row.status, "mode": row.mode,
                            "started_at": row.started_at.isoformat() if row.started_at else None,
                            "finished_at": row.finished_at.isoformat() if row.finished_at else None}
                           for row in rows]
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message, no SQL details
        print(json.dumps({"status": "blocked", "errors": ["scan listing failed"]}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "listed", "scans": payload}, ensure_ascii=False))
    return 0


_MAX_VERIFY_EVIDENCE = 1000
_MAX_VERIFY_FINDINGS = 5000


def _verify(args) -> int:
    """Check that stored report and evidence bytes still match their hashes."""
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.persistence.models import Evidence, Finding, Scan
    from vulnmind.reports.evidence_snapshot import check_evidence_snapshot, check_finding_snapshot
    from vulnmind.reports.loader import load_report
    from vulnmind.reports.store import ReportStore, ReportStoreError

    settings = Settings()
    try:
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        scan_id = UUID(args.scan_id)
        report_store = ReportStore(Path(settings.report_root))
        evidence_store = EvidenceStore(Path(settings.evidence_root)) if settings.evidence_root else None
        engine = create_engine(settings.database_url)
        try:
            with engine.connect() as connection:
                # Ensure all database reads see one snapshot. SQLite's legacy
                # driver otherwise may not begin a transaction for SELECT.
                if connection.dialect.name == "postgresql":
                    connection = connection.execution_options(isolation_level="REPEATABLE READ")
                elif connection.dialect.name == "sqlite":
                    connection.exec_driver_sql("BEGIN")
                with Session(bind=connection) as session:
                    if session.get(Scan, scan_id) is None:
                        raise ValueError("scan is not stored")
                    try:
                        loaded = load_report(session, report_store, scan_id)
                        report_integrity = "valid" if loaded.content is not None else "missing"
                    except (ReportStoreError, UnicodeError):
                        report_integrity = "missing_unreadable_or_invalid"
                    finding_ids = select(Finding.id).where(Finding.scan_id == scan_id)
                    finding_count = session.scalar(select(func.count()).select_from(Finding)
                                                   .where(Finding.scan_id == scan_id))
                    evidence_count = session.scalar(select(func.count()).select_from(Evidence)
                                                    .where(Evidence.finding_id.in_(finding_ids)))
                    evidence_pairs = session.execute(select(Evidence, Finding.fingerprint)
                                                     .join(Finding, Evidence.finding_id == Finding.id)
                                                     .where(Finding.id.in_(finding_ids))
                                                     .order_by(Evidence.id).limit(_MAX_VERIFY_EVIDENCE)).all()
                    evidence_rows = [row for row, _ in evidence_pairs]
                    evidence_limited = evidence_count > len(evidence_pairs)
                    finding_limited = finding_count > _MAX_VERIFY_FINDINGS
                    snapshot_status, missing_snapshot_ids = "not_checked", []
                    finding_snapshot_status, report_only, database_only = "not_checked", 0, 0
                    if report_integrity == "valid":
                        if evidence_limited:
                            snapshot_status = "not_checked_limit"
                        else:
                            snapshot_status, missing_snapshot_ids = check_evidence_snapshot(
                                loaded.content, loaded.format, scan_id, {row.id: fingerprint for row, fingerprint in evidence_pairs})
                        if finding_limited:
                            finding_snapshot_status = "not_checked_limit"
                        else:
                            fingerprints = set(session.scalars(select(Finding.fingerprint).where(Finding.scan_id == scan_id)))
                            finding_snapshot_status, report_only, database_only = check_finding_snapshot(
                                loaded.content, loaded.format, scan_id, fingerprints)
                    findings_without_evidence = session.scalar(
                        select(func.count()).select_from(Finding).where(
                            Finding.scan_id == scan_id,
                            ~select(Evidence.id).where(Evidence.finding_id == Finding.id).exists()))
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["verification failed"]}, ensure_ascii=False))
        return 2
    signature_integrity = "not_checked"
    signature_key_id = None
    if report_integrity == "valid" and loaded.storage_uri is not None:
        from vulnmind.reports.signing import SigningError, resolve_signing_key, verify_bytes

        try:
            signature_key, _ = resolve_signing_key(key=settings.report_signing_key,
                                                    key_file=settings.report_signing_key_file)
        except SigningError:
            signature_key = None
        try:
            stored_signature = report_store.read_signature(loaded.storage_uri)
        except ReportStoreError:
            signature_integrity = "broken"
        else:
            if stored_signature is None:
                signature_integrity = "unsigned"
            elif signature_key is None:
                # A signature exists but this process cannot check it: fail closed.
                signature_integrity = "not_configured"
            else:
                try:
                    record = verify_bytes(loaded.content.encode("utf-8"), stored_signature,
                                          key=signature_key)
                    signature_integrity = "valid"
                    signature_key_id = record.key_id
                except SigningError:
                    signature_integrity = "broken"
    broken = []
    if evidence_store is not None:
        import hashlib

        for row in evidence_rows:
            try:
                data = evidence_store.read(row.content_ref)
            except Exception:  # noqa: BLE001 - any read failure means broken evidence
                broken.append(str(row.id))
                continue
            if row.hash is None or hashlib.sha256(data).hexdigest() != row.hash:
                broken.append(str(row.id))
    report_ok = report_integrity == "valid"
    checked = len(evidence_rows) if evidence_store is not None else 0
    unchecked = evidence_count - checked
    status = ("broken" if not report_ok or broken or snapshot_status in {"broken", "invalid"}
              or finding_snapshot_status == "invalid" or signature_integrity == "broken"
              else "incomplete" if unchecked or findings_without_evidence or snapshot_status == "partial"
              or signature_integrity == "not_configured"
              or finding_snapshot_status in {"incomplete", "not_checked_limit"} else "ok")
    print(json.dumps({"status": status, "scan_id": str(scan_id),
                      "report_present": report_ok, "report_integrity": report_integrity,
                      "signature_integrity": signature_integrity,
                      "signature_key_id": signature_key_id,
                      "evidence_checked": checked,
                      "evidence_unchecked": unchecked, "evidence_broken": broken,
                      "evidence_limit_reached": evidence_limited, "finding_limit_reached": finding_limited,
                      "findings_without_evidence": findings_without_evidence,
                      "evidence_snapshot_integrity": snapshot_status,
                      "evidence_snapshot_missing": missing_snapshot_ids,
                      "finding_snapshot_integrity": finding_snapshot_status,
                      "findings_only_in_report": report_only,
                      "findings_only_in_database": database_only}, ensure_ascii=False))
    return 0 if status == "ok" else 1


def _approval_signer(settings):
    from vulnmind.security.approval_tokens import ApprovalTokenSigner

    secret = settings.approval_secret
    if not secret:
        return None
    return ApprovalTokenSigner(secret)


def _approvals(args) -> int:
    """Operate on the approvals table; no privileged action is executed here."""
    from datetime import timezone
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.security.approvals import ApprovalService

    settings = Settings()
    try:
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if args.approvals_command == "list":
                    service = ApprovalService(session)
                    rows = service.list_pending(UUID(args.scan_id))
                    def expiry_text(value):
                        if value is None:
                            return None
                        if value.utcoffset() is None:
                            value = value.replace(tzinfo=timezone.utc)
                        return value.astimezone(timezone.utc).isoformat()
                    payload = [{"id": str(row.id), "action": row.action, "target": row.target,
                                "operation_hash": row.operation_hash,
                                "expires_at": expiry_text(row.expires_at)}
                               for row in rows]
                    print(json.dumps({"status": "listed", "pending": payload}, ensure_ascii=False))
                    return 0
                if settings.approval_secret and settings.approval_allowed_signers:
                    raise ValueError("configure exactly one approval verifier")
                signer = _approval_signer(settings)
                verifier = None
                if settings.approval_allowed_signers:
                    from vulnmind.security.ssh_approvals import SshSignatureVerifier
                    verifier = SshSignatureVerifier(Path(settings.approval_allowed_signers))
                if signer is None and verifier is None:
                    raise ValueError("approval credentials are required")
                credential = args.credential
                if getattr(args, "local_owner", False):
                    from vulnmind.persistence.models import Approval
                    if signer is None or credential:
                        raise ValueError("local owner mode requires HMAC and no supplied credential")
                    row = session.get(Approval, UUID(args.id))
                    if row is None or row.status != "pending" or row.expires_at is None:
                        raise ValueError("pending approval is required")
                    credential = signer.sign(approval_id=row.id, scan_id=row.scan_id, action=row.action,
                        target=row.target, expires_at=row.expires_at, operation_hash=row.operation_hash, approved=not args.deny)
                service = ApprovalService(session, signer, ssh_verifier=verifier)
                approval = service.decide(UUID(args.id), approver=args.approver,
                                          approved=not args.deny, credential=credential)
                session.commit()
                print(json.dumps({"status": approval.status, "id": str(approval.id),
                                  "approver": approval.approver}, ensure_ascii=False))
                return 0
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - one fixed message, no SQL or credential details
        print(json.dumps({"status": "blocked", "errors": ["approval operation failed"]},
                         ensure_ascii=False))
        return 2


def _read_bounded(path: Path, limit: int) -> str:
    """Read at most ``limit`` bytes, including when the file grows while reading."""
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds the size limit")
    return data.decode("utf-8")


def _show_report(args) -> int:
    """Read a stored report; the database and store roots come from settings."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.reports.loader import load_report
    from vulnmind.reports.store import ReportStore, ReportStoreError

    settings = Settings()
    try:
        if not settings.database_url or not settings.report_root:
            raise ValueError("database and report root must be configured")
        scan_id = UUID(args.scan_id)
        store = ReportStore(Path(settings.report_root))
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                loaded = load_report(session, store, scan_id)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - one fixed message, no exception text or SQL details
        print(json.dumps({"status": "blocked", "errors": ["report is unavailable or unreadable"]},
                         ensure_ascii=False))
        return 2
    if loaded.content is None:
        print(json.dumps({"status": "missing", "scan_id": str(loaded.scan_id),
                          "findings": loaded.findings}, ensure_ascii=False))
        return 2
    if args.json:
        print(json.dumps({"status": "loaded", "scan_id": str(loaded.scan_id), "scan_status": loaded.scan_status,
                          "format": loaded.format, "findings": loaded.findings,
                          "content": loaded.content}, ensure_ascii=False))
    else:
        print(loaded.content, end="")
    return 0








def _fetch(args) -> int:
    """One allowlisted GET through a private network namespace in the WSL sandbox."""
    import socket
    from sqlalchemy import create_engine
    from urllib.parse import urlsplit

    from vulnmind.analysis.sandbox import WslSandbox
    from vulnmind.analysis.sandbox_http import WslCurlTransport
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
    from vulnmind.schemas import Authorization, Target
    from vulnmind.tools.http import HttpRequestInput
    from vulnmind.tools.http_single_hop import SingleHopRequester

    engine = None
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("persistent HTTP audit requires a database")
        engine = create_engine(settings.database_url)
        authorization = Authorization.model_validate_json(_read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        target = Target(type="web", locator=args.url)

        def resolve(host: str) -> list[str]:
            return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})

        requester = SingleHopRequester(DatabaseAuditSink(engine), resolve=resolve,
                                       transport=WslCurlTransport(WslSandbox()))
        response = requester.request(HttpRequestInput(url=args.url, max_response_bytes=args.max_bytes),
                                     actor=args.actor, target=target, scope=authorization)
    except AuditError:
        print(json.dumps({"status": "unknown", "errors": ["HTTP audit is unavailable; inspect audit records before retrying"]}))
        return 2
    except Exception:  # noqa: BLE001 - fixed message without URL or scope details
        print(json.dumps({"status": "blocked", "errors": ["request could not be completed"]},
                         ensure_ascii=False))
        return 2
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps({"status": "ok", "status_code": response.status_code,
                      "final_url": response.final_url, "headers": response.headers,
                      "body_bytes": len(response.body.encode("utf-8")),
                      "truncated": response.truncated, "body": response.body[:2000]},
                     ensure_ascii=False))
    return 0


def _evidence_gc(args) -> int:
    """Dry-run by default; deletion requires --apply and a finished scan's rows."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import SQLAlchemyError

    from vulnmind.config import Settings
    from vulnmind.evidence.gc import EvidenceGcError, referenced_uris, scan_store
    from vulnmind.evidence.coordination import lock_evidence_transaction

    settings = Settings()
    if args.grace_hours < 0 or args.grace_hours > 24 * 365:
        print(json.dumps({"status": "blocked", "errors": ["invalid grace period"]}, ensure_ascii=False))
        return 2
    if not settings.database_url or not settings.evidence_root:
        print(json.dumps({"status": "blocked", "errors": ["evidence store is not configured"]},
                         ensure_ascii=False))
        return 2
    try:
        root = Path(settings.evidence_root).resolve()
        engine = create_engine(settings.database_url)
        try:
            from vulnmind.persistence.audit import DatabaseAuditSink, SessionAuditSink
            gc_call = str(uuid4())
            if args.apply:
                DatabaseAuditSink(engine).record(dict(call_id=gc_call,tool_name='evidence.gc',actor='cli',target_type='repository',status='started'))
            with Session(engine) as session:
                lock_evidence_transaction(session)
                referenced = referenced_uris(session)
                report = scan_store(root, referenced, grace_seconds=args.grace_hours * 3600,
                                    dry_run=not args.apply, coordinated=True)
                if args.apply:
                    SessionAuditSink(session).record(dict(call_id=gc_call,tool_name='evidence.gc',actor='cli',target_type='repository',status='succeeded'))
                    session.commit()
        finally:
            engine.dispose()
    except (EvidenceGcError, ValueError, OSError, RuntimeError, SQLAlchemyError):
        print(json.dumps({"status": "blocked", "errors": ["evidence store could not be scanned"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "ok", "dry_run": report.dry_run, "scanned": report.scanned,
                      "referenced": report.referenced, "orphans": report.orphans,
                      "kept_young": report.kept_young, "unverified": report.unverified,
                      "deleted": report.deleted, "bytes_deleted": report.bytes_deleted,
                      "grace_hours": args.grace_hours}, ensure_ascii=False))
    return 0


def _crawl(args) -> int:
    """GET-only crawl; every fetch goes through the isolated sandbox transport."""
    import socket
    from sqlalchemy import create_engine
    from urllib.parse import urlsplit

    from vulnmind.analysis.crawler import FetchResult, crawl
    from vulnmind.analysis.sandbox import WslSandbox
    from vulnmind.analysis.sandbox_http import WslCurlTransport
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
    from vulnmind.schemas import Authorization, Target
    from vulnmind.tools.http import HttpRequestInput
    from vulnmind.tools.http_single_hop import SingleHopRequester

    if not 1 <= args.max_pages <= 50 or not 1 <= args.max_bytes <= 1_000_000:
        print(json.dumps({"status": "blocked", "errors": ["invalid crawl limits"]}, ensure_ascii=False))
        return 2
    if args.store and not args.project_id:
        print(json.dumps({"status": "blocked", "errors": ["crawl storage requires a project"]},
                         ensure_ascii=False))
        return 2
    scan_id = None
    engine = None
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("persistent HTTP audit requires a database")
        engine = create_engine(settings.database_url)
        project_id = None
        if args.store:
            project_id = UUID(args.project_id)
            _require_project(project_id)
        authorization = Authorization.model_validate_json(_read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        start = Target(type="web", locator=args.start)

        def resolve(name: str) -> list[str]:
            return sorted({item[4][0] for item in socket.getaddrinfo(name, None)})

        requester = SingleHopRequester(DatabaseAuditSink(engine), resolve=resolve,
                                       transport=WslCurlTransport(WslSandbox(), max_body_bytes=min(args.max_bytes, 200_000)))

        def fetch(url: str) -> FetchResult:
            response = requester.request(HttpRequestInput(url=url, max_response_bytes=args.max_bytes),
                                         actor=args.actor, target=Target(type="web", locator=url),
                                         scope=authorization)
            return FetchResult(status_code=response.status_code,
                               content_type=response.headers.get("content-type", ""),
                               body=response.body.encode("utf-8"), final_url=response.final_url,
                               headers=dict(response.headers))

        result = crawl(start=start, scope=authorization, fetch=fetch, max_pages=args.max_pages,
                       max_page_bytes=args.max_bytes)
        if project_id is not None:
            scan_id = _store_crawl(project_id, result.endpoints, args.actor)
    except AuditError:
        print(json.dumps({"status": "unknown", "errors": ["HTTP audit is unavailable; inspect audit records before retrying"]}))
        return 2
    except Exception:  # noqa: BLE001 - fixed message without URL or scope details
        print(json.dumps({"status": "blocked", "errors": ["crawl could not be completed"]},
                         ensure_ascii=False))
        return 2
    finally:
        if engine is not None:
            engine.dispose()
    payload = {"status": "ok", "pages": [page.url for page in result.pages],
               "endpoints": result.endpoints[:200], "endpoint_count": len(result.endpoints),
               "findings": result.findings[:200], "finding_count": len(result.findings),
               "out_of_scope": result.out_of_scope, "errors": result.errors[:20],
               "skipped": result.skipped, "truncated": result.truncated}
    if scan_id is not None:
        payload["scan_id"] = scan_id
    print(json.dumps(payload, ensure_ascii=False))
    return 0


def _require_project(project_id: UUID) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Project

    settings = Settings()
    if not settings.database_url:
        raise ValueError("database URL is not configured")
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            if session.get(Project, project_id) is None:
                raise ValueError("project is not stored")
    finally:
        engine.dispose()


def _store_crawl(project_id: UUID, endpoints: list[dict], actor: str) -> str:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.crawl_store import store_crawl_result
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink

    settings = Settings()
    if not settings.database_url:
        raise ValueError("database URL is not configured")
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session, session.begin():
            audit = SessionAuditSink(session)
            event = {"call_id": str(uuid4()), "tool_name": "web.crawl", "actor": actor,
                     "target_type": "web"}
            audit.record({**event, "status": "requested"})
            scan = store_crawl_result(session=session, project_id=project_id, actor=actor,
                                      endpoints=endpoints)
            audit.record({**event, "status": "pending_commit"})
            return str(scan.id)
    finally:
        engine.dispose()


def _endpoints(args) -> int:
    """List stored web endpoints for one scan; no network access."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Scan
    from vulnmind.persistence.repositories import WebEndpointRepository

    if isinstance(args.limit, bool) or not 1 <= args.limit <= 2000:
        print(json.dumps({"status": "blocked", "errors": ["invalid limit"]}, ensure_ascii=False))
        return 2
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session:
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                rows = WebEndpointRepository(session).list_for_scan(scan_id, limit=args.limit)
                payload = [{"id": str(row.id), "method": row.method, "url": row.url,
                            "source_url": row.source_url, "parameters": row.parameters,
                            "status": row.status} for row in rows]
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["endpoint listing failed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "listed", "scan_id": str(scan_id), "count": len(payload),
                      "endpoints": payload}, ensure_ascii=False))
    return 0


def _shell_request(args) -> int:
    """Record a pending approval bound to the exact command digest; nothing runs here."""
    from datetime import timedelta

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.config import Settings
    from vulnmind.persistence.models import Scan
    from vulnmind.security.approvals import ApprovalService
    from vulnmind.tools.shell import SHELL_ACTION, ShellToolInput, shell_operation_digest

    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        request = ShellToolInput(scan_id=scan_id, argv=args.argv, cwd=args.cwd,
                                 timeout_seconds=args.timeout, env_allowlist=list(args.env),
                                 purpose=args.purpose)
        digest = shell_operation_digest(request)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                approval = ApprovalService(session).request(
                    scan_id=scan_id, action=SHELL_ACTION, target=digest,
                    valid_for=timedelta(hours=72), operation_hash=digest)
                approval_id = str(approval.id)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["shell approval request failed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "requested", "approval_id": approval_id,
                      "operation_digest": digest, "action": SHELL_ACTION}, ensure_ascii=False))
    return 0


def _shell_run(args) -> int:
    """Run one approved, read-only command inside the WSL sandbox."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.sandbox import SandboxError, WslSandbox
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.models import Scan
    from vulnmind.schemas import Authorization, Target
    from vulnmind.security.approvals import ApprovalService
    from vulnmind.security.scope import ScopeDenied
    from vulnmind.tools.shell import SandboxedShellExecutor, ShellDenied, ShellToolInput

    if isinstance(args.max_output_bytes, bool) or not 1 <= args.max_output_bytes <= 1_000_000:
        print(json.dumps({"status": "blocked", "errors": ["invalid output limit"]},
                         ensure_ascii=False))
        return 2
    engine = session = None
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        authorization = Authorization.model_validate_json(_read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        request = ShellToolInput(scan_id=scan_id, argv=args.argv, cwd=args.cwd, purpose=args.purpose,
                                 timeout_seconds=args.timeout, env_allowlist=list(args.env),
                                 approval_token=args.approval_token,
                                 max_output_bytes=args.max_output_bytes)
        target = Target(type="repository", locator=str(Path(args.repository).resolve()))
        engine = create_engine(settings.database_url)
        session = Session(engine)
        if session.get(Scan, scan_id) is None:
            raise ValueError("scan is not stored")
        executor = SandboxedShellExecutor(
            SessionAuditSink(session), approvals=ApprovalService(session), session=session,
            sandbox=WslSandbox(timeout_seconds=args.timeout + 60))
        result = executor.run(request, actor=args.actor, target=target, scope=authorization)
        session.commit()
    except (ShellDenied, ScopeDenied, SandboxError, ValueError, OSError):
        if session is not None:
            try:
                session.commit()
            except Exception:  # noqa: BLE001 - the denial audit is best effort
                session.rollback()
        print(json.dumps({"status": "blocked", "errors": ["shell command could not be completed"]},
                         ensure_ascii=False))
        return 2
    finally:
        if session is not None:
            session.close()
        if engine is not None:
            engine.dispose()
    print(json.dumps({"status": "completed", "call_id": result.call_id,
                      "exit_code": result.exit_code, "timed_out": result.timed_out,
                      "truncated": result.truncated, "duration_ms": result.duration_ms,
                      "output_bytes": result.output_bytes, "output": result.output},
                     ensure_ascii=False))
    return 0


def _doctor(args) -> int:
    """Read-only self-check; never writes, creates directories or prints secrets."""
    from vulnmind.config import Settings
    from vulnmind.doctor import run_checks

    settings = Settings()
    import os
    environment = dict(os.environ)
    for field in ("approval_secret", "approval_allowed_signers", "report_signing_key", "report_signing_key_file"):
        value = getattr(settings, field, None)
        if value is not None:
            environment["VULNMIND_" + field.upper()] = value
    report = run_checks(database_url=settings.database_url, report_root=settings.report_root,
                        evidence_root=getattr(settings, "evidence_root", None), env=environment)
    print(json.dumps(report.model_dump(), ensure_ascii=False))
    return 1 if report.status == "failed" else 0


def _audit_recent(args) -> int:
    from sqlalchemy import create_engine
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import recent_scan_audits
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        engine = create_engine(settings.database_url)
        try:
            with engine.connect() as connection:
                report = recent_scan_audits(connection, limit=args.limit)
        finally:
            engine.dispose()
    except Exception:
        print(json.dumps({"status": "blocked", "errors": ["recent audit lookup unavailable"]}))
        return 2
    print(json.dumps(report))
    return 0


def _audit_trace(args) -> int:
    from sqlalchemy import create_engine
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import trace_scan_audit

    try:
        parent = UUID(args.call_id)
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        engine = create_engine(settings.database_url)
        try:
            with engine.connect() as connection:
                report = trace_scan_audit(connection, parent, limit=args.limit)
        finally:
            engine.dispose()
    except Exception:
        print(json.dumps({"status": "blocked", "errors": ["audit trace unavailable"]}))
        return 2
    print(json.dumps(report))
    return 0


def _audit_verify(args) -> int:
    """Recompute the audit hash chain; a broken chain exits non-zero."""
    from sqlalchemy import create_engine

    from vulnmind.config import Settings
    from vulnmind.persistence.audit import verify_audit_chain

    if isinstance(args.limit, bool) or not 1 <= args.limit <= 10_000:
        print(json.dumps({"status": "blocked", "errors": ["invalid limit"]}, ensure_ascii=False))
        return 2
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        engine = create_engine(settings.database_url)
        try:
            with engine.connect() as connection:
                report = verify_audit_chain(connection, limit=args.limit)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["audit verification failed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "incomplete" if not report.complete else ("valid" if report.valid else "broken"), "checked": report.checked,
                      "unhashed": report.unhashed, "first_break_id": report.first_break_id,
                      "reason": report.reason}, ensure_ascii=False))
    return 0 if report.valid else (2 if not report.complete else 1)


def _planned_probes(args):
    """Resolve --url or --plan-file; exactly one source is required."""
    from vulnmind.analysis.validation import load_plan, plan_probes

    urls = getattr(args, "url", None) or []
    plan_file = getattr(args, "plan_file", None)
    if bool(urls) == bool(plan_file):
        raise ValueError("provide exactly one of --url or --plan-file")
    if plan_file is not None:
        return load_plan(_read_bounded(plan_file, _MAX_REQUEST_BYTES))
    return plan_probes(urls)


def _validate_request(args) -> int:
    """Record a pending approval bound to an exact validation plan; nothing is sent."""
    from datetime import timedelta

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.validation import plan_digest
    from vulnmind.config import Settings
    from vulnmind.persistence.models import Scan
    from vulnmind.security.approvals import ApprovalService

    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        probes = _planned_probes(args)
        digest = plan_digest(probes)
        engine = create_engine(settings.database_url)
        try:
            with Session(engine) as session, session.begin():
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                approval = ApprovalService(session).request(
                    scan_id=scan_id, action="validation.probes", target=digest,
                    valid_for=timedelta(hours=72), operation_hash=digest)
                approval_id = str(approval.id)
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 - fixed message
        print(json.dumps({"status": "blocked", "errors": ["validation approval request failed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "requested", "approval_id": approval_id,
                      "operation_digest": digest, "probe_count": len(probes),
                      "action": "validation.probes"}, ensure_ascii=False))
    return 0


def _validate_run(args) -> int:
    """Run approved non-destructive probes through the isolated WSL transport."""
    import socket

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.analysis.crawler import FetchResult
    from vulnmind.analysis.sandbox import WslSandbox
    from vulnmind.analysis.sandbox_http import WslCurlTransport
    from vulnmind.analysis.validation import ValidationDenied, ValidationEngine, ValidationStateUnknown
    from vulnmind.config import Settings
    from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
    from vulnmind.persistence.models import Scan
    from vulnmind.schemas import Authorization, Target
    from vulnmind.security.approvals import ApprovalService
    from vulnmind.security.scope import ScopeDenied
    from vulnmind.tools.http import HttpRequestInput
    from vulnmind.tools.http_single_hop import SingleHopRequester

    if not 1 <= args.max_bytes <= 1_000_000:
        print(json.dumps({"status": "blocked", "errors": ["invalid byte limit"]}, ensure_ascii=False))
        return 2
    engine = session = None
    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        scan_id = UUID(args.scan_id)
        authorization = Authorization.model_validate_json(_read_bounded(args.scope_file, _MAX_REQUEST_BYTES))
        probes = _planned_probes(args)

        def resolve(name: str) -> list[str]:
            return sorted({item[4][0] for item in socket.getaddrinfo(name, None)})

        engine = create_engine(settings.database_url)
        audit = DatabaseAuditSink(engine)
        requester = SingleHopRequester(audit, resolve=resolve,
                                       transport=WslCurlTransport(WslSandbox(), max_body_bytes=args.max_bytes))

        def fetch(url: str) -> FetchResult:
            response = requester.request(HttpRequestInput(url=url, max_response_bytes=args.max_bytes),
                                         actor=args.actor, target=Target(type="web", locator=url),
                                         scope=authorization)
            return FetchResult(status_code=response.status_code,
                               content_type=response.headers.get("content-type", ""),
                               body=response.body.encode("utf-8"), final_url=response.final_url,
                               headers=dict(response.headers))

        session = Session(engine)
        if session.get(Scan, scan_id) is None:
            raise ValueError("scan is not stored")
        runner = ValidationEngine(audit, approvals=ApprovalService(session),
                                  session=session)
        report = runner.run(probes, fetch=fetch, actor=args.actor, scan_id=scan_id,
                            approval_token=args.approval_token)
        session.commit()
    except (AuditError, ValidationStateUnknown):
        if session is not None:
            session.rollback()
        print(json.dumps({"status": "unknown", "errors": ["validation audit is unavailable; inspect approval and audit records before retrying"]}))
        return 2
    except (ValidationDenied, ScopeDenied, ValueError, OSError):
        if session is not None:
            try:
                session.commit()
            except Exception:  # noqa: BLE001 - denial audit is best effort
                session.rollback()
        print(json.dumps({"status": "blocked", "errors": ["validation could not be completed"]},
                         ensure_ascii=False))
        return 2
    finally:
        if session is not None:
            session.close()
        if engine is not None:
            engine.dispose()
    print(json.dumps({"status": "completed", "candidates": report.candidates,
                      "inconclusive": report.inconclusive, "errors": report.errors,
                      "approval_digest": report.approval_digest,
                      "results": [result.model_dump() for result in report.results]},
                     ensure_ascii=False))
    return 0


def _validation_plan(args) -> int:
    """Model-assisted probe selection over stored endpoints; no request is sent."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from vulnmind.agents.audit import AgentAuditBridge
    from vulnmind.agents.deepseek import DeepSeekClient
    from vulnmind.agents.form_candidates import form_candidate_urls
    from vulnmind.agents.runtime import AgentRuntime
    from vulnmind.agents.validation_plan import MAX_SELECTIONS, select_probes
    from vulnmind.config import Settings
    from vulnmind.persistence.scan_audit import ScanCommitUnknown, repository_scan_transaction
    from vulnmind.persistence.models import Scan
    from vulnmind.persistence.repositories import WebEndpointRepository

    try:
        settings = Settings()
        if not settings.database_url:
            raise ValueError("database URL is not configured")
        if isinstance(args.limit, bool) or not 1 <= args.limit <= 2000:
            raise ValueError("limit must be between 1 and 2000")
        if isinstance(args.max_selections, bool) or not 1 <= args.max_selections <= MAX_SELECTIONS:
            raise ValueError("max selections is out of range")
        scan_id = UUID(args.scan_id)
        client = DeepSeekClient(model=args.agent_model) if args.agent_model else DeepSeekClient()
        engine = create_engine(settings.database_url)
        try:
            with repository_scan_transaction(engine, actor=args.actor, target_type="web", action="validation-plan") as (session, audit, audit_call_id):
                if session.get(Scan, scan_id) is None:
                    raise ValueError("scan is not stored")
                rows = WebEndpointRepository(session).list_for_scan(scan_id, limit=args.limit)
                endpoint_list_may_be_truncated = len(rows) == args.limit
                parameters_unknown_endpoints = sum(row.method == "GET" and row.parameters is None for row in rows)
                urls, omitted_forms = form_candidate_urls(rows)
                event = {"call_id": str(uuid4()), "tool_name": "web.validation-plan",
                         "actor": args.actor, "target_type": "web"}
                audit.record({**event, "status": "requested"})
                runtime = AgentRuntime(client, AgentAuditBridge(audit, target_type="web"))
                plan = select_probes(runtime, actor=args.actor, urls=urls,
                                     max_selections=args.max_selections)
                audit.record({**event, "status": "succeeded" if plan.status == "completed"
                              else ("failed" if plan.status == "failed" else "succeeded")})
        finally:
            engine.dispose()
        payload = {"version": 1, "digest": plan.digest,
                   "probes": [item.probe.model_dump(mode="json") for item in plan.selected]}
        if args.output is not None and plan.selected:
            args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except ScanCommitUnknown:
        print(json.dumps({"status": "unknown", "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["planning audit or commit is uncertain; inspect records before retrying"]}))
        return 2
    except Exception:  # noqa: BLE001 - fixed message, no target or model details
        print(json.dumps({"status": "blocked", "audit_call_id": locals().get("audit_call_id"),
                          "errors": ["validation plan could not be built"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": plan.status, "scan_id": str(scan_id),
                      "audit_call_id": audit_call_id,
                      "candidate_count": plan.candidates, "candidates_truncated": plan.candidates_truncated,
                      "selected_count": len(plan.selected),
                      "digest": plan.digest, "summary": plan.summary, "ignored": plan.ignored,
                      "form_parameters_omitted": omitted_forms,
                      "parameters_unknown_endpoints": parameters_unknown_endpoints,
                      "endpoint_list_may_be_truncated": endpoint_list_may_be_truncated,
                      "probes": [{"kind": item.probe.kind, "url": item.probe.url,
                                  "parameter": item.probe.parameter, "reason": item.reason}
                                 for item in plan.selected],
                      "note": "selection only; form values are synthetic empty placeholders; candidates are capped; "
                              "no request was sent; approve with "
                              "validate-request --plan-file"}, ensure_ascii=False))
    return 0 if plan.status in {"completed", "skipped"} else 1


def _knowledge_ask(args) -> int:
    """Retrieve bounded references and explicitly send them to a model."""
    if not args.send_to_model:
        print(json.dumps({"status": "blocked", "errors": ["explicit --send-to-model is required"]}))
        return 2
    if not isinstance(args.question, str) or not args.question.strip() or len(args.question) > 2000:
        print(json.dumps({"status": "blocked", "errors": ["invalid question"]}))
        return 2
    if args.output is not None and (args.output.exists() or not args.output.parent.is_dir()):
        print(json.dumps({"status": "blocked", "errors": ["output must be a new file in an existing directory"]}))
        return 2
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from vulnmind.agents.audit import AgentAuditBridge
    from vulnmind.agents.deepseek import DeepSeekClient
    from vulnmind.agents.runtime import AgentRuntime
    from vulnmind.config import Settings
    from vulnmind.knowledge.answer import answer_question
    from vulnmind.knowledge.hybrid import LocalQueryEncoder, PostgresHybridRetriever
    from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
    from vulnmind.persistence.audit import DatabaseAuditSink

    engine = None
    def emit(output):
        if args.output is not None:
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(output, stream, ensure_ascii=False, indent=2)
        print(json.dumps(output, ensure_ascii=False))

    stage = "configuration"
    try:
        settings = Settings()
        if not settings.database_url or not settings.database_url.startswith("postgresql"):
            raise ValueError("PostgreSQL is required")
        engine = create_engine(settings.database_url)
        if args.retrieval != "hybrid":
            raise ValueError("only hybrid retrieval is supported")
        stage = "local_embedding"
        encoder = LocalQueryEncoder()
        stage = "retrieval"
        with Session(engine) as session, session.begin():
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            retrieval = PostgresHybridRetriever(session, encoder=encoder).search_with_diagnostics(args.question, limit=10)
            identifiers = list(retrieval.identifiers)
            store = DatabaseChunkStore(session)
            chunks = [store.get(identifier) for identifier in identifiers]
            if any(chunk is None or chunk.chunk_id != identifier for identifier, chunk in zip(identifiers, chunks)):
                raise ValueError("retrieved knowledge is missing")
        if not chunks:
            output = {"status": "no_context", "answer": "", "references": [], "omitted": 0,
                      "retrieval": args.retrieval, "retrieval_diagnostics": {
                          "sparse_count": retrieval.sparse_count, "dense_count": retrieval.dense_count,
                          "sparse_limit_reached": retrieval.sparse_limit_reached,
                          "dense_limit_reached": retrieval.dense_limit_reached, "fused": list(retrieval.fused)},
                      "note": "no matching knowledge; no model call was made"}
            stage = "output"
            emit(output)
            return 0
        stage = "model_or_citations"
        runtime = AgentRuntime(DeepSeekClient(), AgentAuditBridge(DatabaseAuditSink(engine), target_type="knowledge"))
        result = answer_question(args.question, chunks, runtime, actor=args.actor,
                                 review_runtime=runtime)
        output = result.model_dump(mode="json")
        output.update({"retrieval": args.retrieval,
                       "retrieval_diagnostics": {"sparse_count": retrieval.sparse_count,
                           "dense_count": retrieval.dense_count,
                           "sparse_limit_reached": retrieval.sparse_limit_reached,
                           "dense_limit_reached": retrieval.dense_limit_reached,
                           "fused": list(retrieval.fused)},
                       "note": "untrusted reference-based answer; citations are not independent verification"})
        stage = "output"
        emit(output)
        return 0
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001 - never expose credentials, query or provider internals
        print(json.dumps({"status": "blocked", "stage": stage,
                          "errors": ["knowledge question could not be completed"]}))
        return 2
    finally:
        if engine is not None:
            engine.dispose()


def _agent_run(args) -> int:
    """One agent call; the API key is read from the environment and never printed."""
    from pydantic import BaseModel, ConfigDict, Field

    from vulnmind.agents.deepseek import DeepSeekClient
    from vulnmind.agents.model import ModelError
    from vulnmind.agents.prompts import DEFAULT_SPECS
    from vulnmind.agents.runtime import AgentError, AgentRuntime
    from vulnmind.context.builder import ContextItem

    class AgentReply(BaseModel):
        model_config = ConfigDict(extra="forbid")
        summary: str = Field(min_length=1, max_length=4000)
        items: list[dict[str, str]] = Field(default_factory=list, max_length=50)

    class _Audit:
        def record(self, event):
            return None

    try:
        context: list[ContextItem] = []
        if args.context_file is not None:
            raw = json.loads(_read_bounded(args.context_file, _MAX_REQUEST_BYTES))
            if not isinstance(raw, list) or len(raw) > 50:
                raise ValueError("context must be a list of at most 50 references")
            context = [ContextItem.model_validate(item) for item in raw]
        spec = DEFAULT_SPECS[args.role]
        client = DeepSeekClient(model=args.model) if args.model else DeepSeekClient()
        runtime = AgentRuntime(client, _Audit())
        output = runtime.run(spec, task=args.task, context=context, schema=AgentReply,
                             actor=args.actor)
    except (ValueError, ModelError, AgentError, OSError):
        print(json.dumps({"status": "blocked", "errors": ["agent call could not be completed"]},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"status": "ok", "role": args.role, "spec": output.spec,
                      "data": output.data.model_dump(), "attempts": output.attempts,
                      "usage": output.usage.model_dump()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
