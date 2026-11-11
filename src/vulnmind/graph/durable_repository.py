"""Repository multi-agent graph. Every node resumes from an atomic journal receipt."""
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict
from uuid import UUID, uuid5

from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.persistence.durable import Journal, digest, workflow_lock
from vulnmind.persistence.models import (Scan, ScanTask, AgentRun, Finding, Evidence,
                                        MemoryRecordRow, ContextManifestRecord)
from vulnmind.schemas import Target, Authorization
from vulnmind.security.scope import check_target


STAGES = ("initialize", "plan", "analyze", "evidence", "knowledge", "analyst",
          "triage", "writer", "report", "memory", "finalize")


class FlowState(TypedDict, total=False):
    results: dict
    status: str
    last_stage: str


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=1500)


def encode_analysis(analysis):
    data = analysis.model_dump(mode="python")
    for item in data["evidence"]:
        item["content"] = base64.b64encode(item["content"]).decode("ascii")
    # The remaining fields use only JSON primitives (candidate statuses are strings).
    return data


def decode_analysis(data):
    from vulnmind.analysis.repository import RepositoryAnalysis
    copied = {**data, "evidence": [{**item, "content": base64.b64decode(item["content"], validate=True)}
                                  for item in data["evidence"]]}
    return RepositoryAnalysis.model_validate(copied)


class RepositoryFlow:
    def __init__(self, engine, workflow_id, project_id, target, scope, options, *, client_factory=None, external=None):
        self.engine, self.workflow_id, self.project_id = engine, workflow_id, project_id
        self.target, self.scope, self.options = target, scope, options
        self.scan_id = uuid5(workflow_id, "scan-v2")
        self.actor = options["actor"]
        self.client_factory = client_factory
        self.external = external
        self.journal = Journal(engine, workflow_id, {"version": 2, "project": str(project_id),
            "target": target.model_dump(mode="json"), "scope": scope.model_dump(mode="json"), "options": options}, self.actor)

    def runtime(self, audit):
        from vulnmind.agents.runtime import AgentRuntime
        from vulnmind.agents.audit import AgentAuditBridge
        from vulnmind.agents.deepseek import DeepSeekClient
        client = self.client_factory() if self.client_factory else DeepSeekClient(model=self.options["agent_model"])
        return AgentRuntime(client, AgentAuditBridge(audit, target_type="repository"), max_attempts=2)

    def compute(self, stage, prior, audit):
        opts = self.options
        if stage == "initialize":
            return {"scan_id": str(self.scan_id)}
        if stage == "plan":
            from vulnmind.agents.tool_plan import select_repository_tools
            enabled = set(opts["tools"])
            selected = select_repository_tools(self.runtime(audit), enabled=enabled, actor=self.actor) if opts["agent_plan"] else sorted(enabled)
            return {"selected_tools": list(selected), "omitted_tools": sorted(enabled - set(selected))}
        if stage == "analyze":
            from vulnmind.analysis.repository import RepositoryPipeline
            from vulnmind.analysis.python_tls import find_python_tls_candidates
            from vulnmind.tools.repo_files import RepositoryReader
            from vulnmind.tools.repo_access import RepositoryAccess
            from vulnmind.analysis.repo_analyzers import (
                McpCheckovAnalyzer, SandboxedGitleaksAnalyzer, SandboxedTrivyAnalyzer, SarifReportAnalyzer,
            )
            from vulnmind.analysis.bandit import BanditReportAnalyzer
            from vulnmind.analysis.sandbox import WslSandbox
            analyzers = []
            for name in prior["plan"]["selected_tools"]:
                if name == "gitleaks_sandbox":
                    analyzers.append(SandboxedGitleaksAnalyzer(WslSandbox(), target_id="repository"))
                elif name == "trivy_sandbox":
                    analyzers.append(SandboxedTrivyAnalyzer(WslSandbox(), target_id="repository"))
                elif name == "checkov_mcp":
                    analyzers.append(McpCheckovAnalyzer(
                        target_id="repository",
                        external_root=Path(opts["external_root"]) if opts.get("external_root") else None,
                        external_service=self.external,
                    ))
                else:
                    item = opts["reports"][name]
                    cls = SarifReportAnalyzer if name == "semgrep_sarif" else BanditReportAnalyzer
                    analyzers.append(cls(Path(item["path"]), target_id="repository", expected_sha256=item["sha256"]))
            reader = RepositoryReader(audit)
            analysis = RepositoryPipeline(reader, [find_python_tls_candidates],
                access=RepositoryAccess(reader, audit), repo_analyzers=analyzers).run(
                    scan_id=str(self.scan_id), project_id=str(self.project_id), target=self.target,
                    scope=self.scope, actor=self.actor)
            return encode_analysis(analysis)
        analysis = decode_analysis(prior["analyze"])
        if stage == "evidence":
            return {"stored": 0}
        if stage == "knowledge":
            extra = self.context_snapshot(analysis)
            if not opts["knowledge_context"] and not opts["agent_knowledge"]:
                return {"status": "disabled", **extra}
            from vulnmind.context.scan_manifest import knowledge_manifest_provider
            from vulnmind.knowledge.hybrid import LocalQueryEncoder, PostgresHybridRetriever
            from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
            with Session(self.engine) as session:
                store = DatabaseChunkStore(session)
                retriever = PostgresHybridRetriever(session, encoder=LocalQueryEncoder())
                manifest = knowledge_manifest_provider(retriever, store, retrieval_method="hybrid")(analysis)
                chunks = []
                # Freeze the selected reference bodies so later agents consume
                # the same knowledge snapshot on every resume.
                for item in manifest["selected_refs"]["knowledge"]:
                    if item["selected"]:
                        chunks.append(store.get(item["chunk_id"]).model_dump(mode="json"))
                return {"status": "selected", "manifest": manifest, "chunks": chunks, **extra}
        if stage == "analyst":
            if not opts["agent_analysis"] and not opts["agent_knowledge"]:
                return {"status": "disabled"}
            from vulnmind.agents.prompts import REPOSITORY_ANALYST
            return self.advisory(REPOSITORY_ANALYST, prior, audit, use_knowledge=opts["agent_knowledge"])
        if stage == "triage":
            from vulnmind.analysis.triage import triage_groups
            from vulnmind.agents.review import review_findings
            result = {"decisions": [item.model_dump(mode="json") for item in triage_groups(analysis.groups)], "review": None}
            if opts["agent_review"]:
                review = review_findings(self.runtime(audit), actor=self.actor, groups=analysis.groups,
                                        advisory_context=prior["analyst"].get("summary"))
                if review.status == "failed":
                    raise RuntimeError("advisory review did not complete")
                result["review"] = review.model_dump(mode="json")
            return result
        if stage == "writer":
            if not opts["agent_report"]:
                return {"status": "disabled"}
            from vulnmind.agents.prompts import REPORT_WRITER
            return self.advisory(REPORT_WRITER, prior, audit)
        if stage == "report":
            from vulnmind.reports.generator import generate, DecisionSummary
            from vulnmind.analysis.service import _report_review
            from vulnmind.agents.review import AgentReview
            limitations = ["仅静态分析；模型结论是未经验证的建议；发现仍需人工确认"]
            limitations.extend(f"规划未选择扫描器: {name}" for name in prior["plan"]["omitted_tools"])
            for name in ("analyst", "writer"):
                if prior[name].get("summary"):
                    limitations.append(f"{name} 模型建议（未验证）: {prior[name]['summary']}")
            review = prior["triage"]["review"]
            report_input = analysis.to_report_input(limitations=limitations,
                decisions=[DecisionSummary.model_validate({k: v for k, v in item.items() if k != "status"})
                           for item in prior["triage"]["decisions"]],
                agent_review=_report_review(AgentReview.model_validate(review)) if review else None)
            report_input = report_input.model_copy(update={"evidence_record_ids": prior["evidence"]["ids"],
                "evidence_snapshot": "available"})
            report = generate(report_input, format=opts["report_format"])
            return {"content": report.content, "format": report.format}
        if stage == "memory":
            return {"scan_id": str(self.scan_id), "report_uri": prior["report"]["uri"],
                    "finding_count": len(analysis.groups), "interpretation": "unverified_static_analysis",
                    "stage_receipts": {name: digest(value) for name, value in prior.items()}}
        if stage == "finalize":
            self.verify(prior)
            return {"scan_id": str(self.scan_id), "report_uri": prior["report"]["uri"]}
        raise ValueError("unknown stage")

    def advisory(self, spec, prior, audit, use_knowledge=False):
        from vulnmind.agents.review import _context_item
        from vulnmind.context.builder import ContextItem
        analysis = decode_analysis(prior["analyze"])
        context = [_context_item(i, group) for i, group in enumerate(analysis.groups[:25])]
        context.extend(ContextItem.model_validate(item) for item in prior['knowledge'].get('extra_context', []))
        if use_knowledge:
            for item in prior["knowledge"].get("chunks", [])[:8]:
                context.append(ContextItem(ref=f"knowledge:{item['chunk_id']}", kind="rag", text=item["content"][:2500]))
        # Pass prior agent opinions explicitly as untrusted reference data.
        if spec.role == "report" and prior.get("analyst", {}).get("summary"):
            context.append(ContextItem(ref="agent:analyst", kind="execution", text=prior["analyst"]["summary"]))
        if spec.role == "report":
            import json
            context.append(ContextItem(ref="agent:triage", kind="execution",
                text=json.dumps(prior["triage"], ensure_ascii=False)[:5000]))
        result = self.runtime(audit).run(spec, task=(
            "Summarize supplied metadata and limitations in fewer than 500 characters. "
            "Return exactly one JSON object containing only the key summary with a string value. "
            "Do not add any other keys. Do not claim verification or invent evidence."),
            context=context, schema=Advisory, actor=self.actor)
        return {"status": "advisory", "summary": result.data.summary, "usage": result.usage.model_dump(mode="json")}

    def context_snapshot(self, analysis):
        from vulnmind.context.builder import ContextItem
        items = []
        if self.options.get('skills'):
            from vulnmind.knowledge.skills import SkillLoader
            loader = SkillLoader(Path(self.options['skills']))
            kinds = {c.vulnerability_type for g in analysis.groups for c in g.candidates}
            for metadata in loader.select(target_type='repository'):
                if metadata.vuln_type and metadata.vuln_type not in kinds:
                    continue
                skill = loader.load(metadata.skill_id)
                items.append(ContextItem(ref=f'skill:{skill.skill_id}@{skill.version}#{skill.sha256}', kind='skill', text=skill.content[:4000]))
                if len(items) >= 8:
                    break
        if self.options.get('use_memory'):
            from vulnmind.persistence.repositories import MemoryRepository
            with Session(self.engine) as session:
                memories = MemoryRepository(session).query_active(project_id=str(self.project_id), task_id=str(uuid5(self.workflow_id, 'task:initialize')))
                for record in memories[:8]:
                    if record.level == 'long_term' and record.validated_by:
                        items.append(ContextItem(ref=f'memory:{record.id}', kind='memory', text=record.content[:4000]))
        return {'extra_context': [item.model_dump(mode='json') for item in items]} if items else {}

    def persist(self, stage, prior, session, output):
        if stage == "initialize":
            session.add(Scan(id=self.scan_id, project_id=self.project_id, status="running", mode="analysis",
                             started_at=datetime.now(timezone.utc)))
            session.flush()
        task_id, run_id = uuid5(self.workflow_id, "task:" + stage), uuid5(self.workflow_id, "run:" + stage)
        session.add(ScanTask(id=task_id, scan_id=self.scan_id, phase=stage, agent_name=stage, status="finished"))
        session.flush()
        session.add(AgentRun(id=run_id, task_id=task_id, agent_name=stage, status="succeeded",
                            input_ref=f"workflow:{self.workflow_id}", output_ref=f"stage:{stage}"))
        session.flush()
        if stage == "evidence":
            from vulnmind.analysis.persistence import FindingWriter
            from vulnmind.evidence.ingest import ingest_evidence, EvidenceItem
            from vulnmind.evidence.store import EvidenceStore
            analysis = decode_analysis(prior["analyze"])
            FindingWriter(session).store(self.scan_id, analysis)
            count = 0
            if self.options["evidence_root"] and analysis.evidence:
                count = ingest_evidence(session, EvidenceStore(Path(self.options["evidence_root"])), scan_id=self.scan_id,
                    items=[EvidenceItem(**item.model_dump()) for item in analysis.evidence]).stored
            ids = {}
            for fingerprint, evidence_id in session.execute(select(Finding.fingerprint, Evidence.id)
                    .join(Evidence, Evidence.finding_id == Finding.id).where(Finding.scan_id == self.scan_id)):
                ids.setdefault(fingerprint, []).append(str(evidence_id))
            output = {"stored": count, "ids": ids}
        if stage == "knowledge" and "manifest" in output:
            manifest = output["manifest"]
            session.add(ContextManifestRecord(id=uuid5(self.workflow_id, "manifest"), run_id=run_id,
                agent_name="knowledge", selected_refs=manifest["selected_refs"], token_estimate=manifest["token_estimate"]))
        if stage == "report":
            from vulnmind.reports.store import ReportStore
            from vulnmind.persistence.repositories import ReportRepository
            ref = ReportStore(Path(self.options["report_root"])).put(output["content"], format=output["format"])
            from vulnmind.reports.signing import sign_configured
            sign_configured(ReportStore(Path(self.options['report_root'])), ref.uri)
            ReportRepository(session).create(self.scan_id, format=output["format"], storage_uri=ref.uri)
            output = {"uri": ref.uri, "format": output["format"]}
        if stage == "memory":
            import json
            session.add(MemoryRecordRow(id=uuid5(self.workflow_id, "memory"), level="working",
                project_id=self.project_id, task_id=task_id, memory_type="workflow_receipt",
                content=json.dumps(output, sort_keys=True), source_refs=[f"scan:{self.scan_id}", output["report_uri"]],
                confidence=0.0, validated_by=None, invalidated=False, created_at=datetime.now(timezone.utc)))
        if stage == "finalize":
            scan = session.get(Scan, self.scan_id)
            scan.status, scan.finished_at = "finished", datetime.now(timezone.utc)
        return output

    def verify(self, prior):
        from vulnmind.reports.store import ReportStore
        from vulnmind.reports.identity import matches_scan
        from vulnmind.evidence.store import EvidenceStore
        from vulnmind.persistence.models import Report
        with Session(self.engine) as session:
            scan = session.get(Scan, self.scan_id)
            if scan is None or scan.project_id != self.project_id:
                raise ValueError("scan identity mismatch")
            receipt = prior["report"]
            record = session.scalar(select(Report).where(Report.scan_id == self.scan_id,
                Report.storage_uri == receipt["uri"], Report.format == receipt["format"]))
            content = ReportStore(Path(self.options["report_root"])).read(receipt["uri"])
            if record is None or not matches_scan(content, receipt["format"], scan_id=self.scan_id, project_id=self.project_id):
                raise ValueError("report integrity failed")
            # EvidenceStore verifies each content-addressed file on read.
            if self.options["evidence_root"]:
                store = EvidenceStore(Path(self.options["evidence_root"]))
                found = {}
                for row, fingerprint in session.execute(select(Evidence, Finding.fingerprint)
                        .join(Finding, Evidence.finding_id == Finding.id).where(Finding.scan_id == self.scan_id)):
                    from hashlib import sha256
                    if sha256(store.read(row.content_ref)).hexdigest() != row.hash:
                        raise ValueError("evidence record hash mismatch")
                    found.setdefault(fingerprint, []).append(str(row.id))
                if {k: sorted(v) for k, v in found.items()} != {k: sorted(v) for k, v in prior["evidence"]["ids"].items()}:
                    raise ValueError("evidence identity mismatch")

    def run(self, *, pause_after=None, reconcile=False):
        def node(stage):
            def execute(state):
                check_target(self.target, self.scope)
                prior = state.get("results", {})
                output = self.journal.run(stage, {name: digest(value) for name, value in prior.items()},
                    lambda audit: self.compute(stage, prior, audit),
                    persist=lambda session, value: self.persist(stage, prior, session, value),
                    replay_safe=stage in {"initialize", "evidence", "knowledge", "report", "memory", "finalize"},
                    read_only=reconcile)
                return {"results": {**prior, stage: output}, "last_stage": stage,
                        "status": "paused" if stage == pause_after else "running"}
            return execute
        graph = StateGraph(FlowState)
        for index, stage in enumerate(STAGES):
            graph.add_node(stage, node(stage))
            following = STAGES[index + 1] if index + 1 < len(STAGES) else END
            graph.add_conditional_edges(stage, lambda state: state["status"] == "paused", {True: END, False: following})
        graph.add_edge(START, STAGES[0])
        with workflow_lock(self.engine, self.workflow_id):
            state = graph.compile().invoke({"results": {}})
            if state["status"] != "paused":
                check_target(self.target, self.scope)
                self.verify(state["results"])
            return {"status": "paused" if state["status"] == "paused" else "finished",
                    "workflow_id": str(self.workflow_id), "scan_id": str(self.scan_id), "last_stage": state["last_stage"]}
