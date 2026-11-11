"""Single-attempt repository graph, used by the limited workflow-scan CLI.

The executor must return a scan UUID only after its own transaction commits.
This graph does not make database and filesystem effects atomic or support
active HTTP. An explicitly supplied reconciler can recover certain committed
scans; never retry a started operation solely because its checkpoint is missing.
"""
from hashlib import sha256
import json
from uuid import UUID

from langgraph.graph import END, START, StateGraph

from vulnmind.graph.state import VulnMindState
from vulnmind.persistence.workflow_operations import claim_stage, complete_stage, lookup_stage
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target


def _request(state):
    workflow_id = UUID(state["task_id"])
    project_id = UUID(state["project_id"])
    targets = [Target.model_validate(item) for item in state["targets"]]
    scope = Authorization.model_validate(state["authorized_scope"])
    if len(targets) != 1 or targets[0].type.value != "repository":
        raise ValueError("one repository target is required")
    options = state.get("workflow_options", {})
    if not isinstance(options, dict):
        raise ValueError("invalid workflow options")
    check_target(targets[0], scope)
    payload = {"project_id": str(project_id), "target": targets[0].model_dump(mode="json"),
               "scope": scope.model_dump(mode="json"), "options": options}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    if len(encoded) > 100_000:
        raise ValueError("workflow request is too large")
    return workflow_id, sha256(encoded).hexdigest()


def build_guarded_repository_graph(engine, executor, checkpointer=None, *, reconcile_only=False,
                                   reconciler=None, plan_executor=None, plan_prepare=None, report_verifier=None,
                                   knowledge_executor=None, knowledge_prepare=None, knowledge_verifier=None):
    """Build a graph around a caller-supplied, independently committing executor.

    The callback receives the graph state and must return the UUID of its
    committed scan. The caller must include every execution-relevant option in
    workflow_options. The CLI supplies a durable planner when explicitly enabled.
    """
    if not callable(executor):
        raise ValueError("an executor is required")
    if reconcile_only and not callable(reconciler):
        raise ValueError("a reconciler is required")
    if plan_executor is not None and not callable(plan_executor):
        raise ValueError("plan executor must be callable")
    if plan_prepare is not None and not callable(plan_prepare):
        raise ValueError("plan preparation must be callable")
    if report_verifier is not None and not callable(report_verifier):
        raise ValueError("report verifier must be callable")
    if knowledge_executor is not None and (not callable(knowledge_executor) or not callable(knowledge_verifier)
                                           or not callable(report_verifier)):
        raise ValueError("knowledge stage requires executor, verifier and report check")
    if knowledge_prepare is not None and not callable(knowledge_prepare):
        raise ValueError("knowledge preparation must be callable")

    def scan_result(scan_id, operation_id):
        return {"status": "scan_recorded" if report_verifier else "finished",
                "errors": [], "report": ({"scan_id": str(scan_id), "operation_id": str(operation_id)}
                                           if report_verifier else {"scan_id": str(scan_id)})}

    def scope(state):
        clear = {"report": {}, "findings": [], "decisions": [], "analysis": {},
                 "evidence_refs": [], "plan": {}, "mock_results": []}
        try:
            _request(state)
        except (ValueError, TypeError, KeyError, OverflowError):
            return {"status": "blocked", "errors": ["invalid or unauthorized request"], **clear}
        return {"status": "authorized", "errors": [], **clear}

    def execute(state):
        try:
            # Recheck on graph resume, not just on the original transition.
            workflow_id, digest = _request(state)
        except (ValueError, TypeError, KeyError, OverflowError):
            return {"status": "blocked", "errors": ["invalid or unauthorized request"], "report": {}}
        try:
            claim = (lookup_stage(engine, workflow_id=workflow_id, stage="repository_scan", input_digest=digest)
                     if reconcile_only else
                     claim_stage(engine, workflow_id=workflow_id, stage="repository_scan", input_digest=digest))
        except ValueError:
            return {"status": "blocked", "errors": ["workflow identity does not match"], "report": {}}
        except Exception:
            return {"status": "unknown", "errors": ["operation claim could not be confirmed"], "report": {}}
        if claim is None:
            return {"status": "blocked", "errors": ["workflow operation was not found"], "report": {}}
        if claim.status == "unknown" and reconcile_only:
            try:
                if reconciler(workflow_id, claim.operation_id, digest, state):
                    return scan_result(claim.operation_id, claim.operation_id)
            except Exception:
                pass
            return {"status": "unknown", "errors": ["committed scan could not be independently verified"], "report": {}}
        if claim.status == "unknown":
            return {"status": "unknown", "errors": ["prior operation requires reconciliation"], "report": {}}
        if claim.status == "completed":
            return scan_result(claim.result_id, claim.operation_id)
        try:
            # Expose the stable operation ID to the executor so it can bind
            # its persisted scan and root audit to the same correlation ID.
            scan_id = executor({**state, "workflow_operation_id": str(claim.operation_id)})
            if not isinstance(scan_id, UUID):
                raise ValueError("executor did not return a scan UUID")
            complete_stage(engine, operation_id=claim.operation_id, owner_token=claim.owner_token,
                           result_id=scan_id)
        except Exception:
            # No distinction between a failed effect and an effect whose
            # result or commit acknowledgement was lost; never replay it.
            return {"status": "unknown", "errors": ["scan outcome requires reconciliation"], "report": {}}
        return scan_result(scan_id, claim.operation_id)

    def verify_report(state):
        try:
            # This read-only node can safely be repeated, but must not use a
            # stale authorization after an interrupted or long-running scan.
            _request(state)
            scan_id = UUID(state["report"]["scan_id"])
            if report_verifier(state, scan_id) is not True:
                raise ValueError("report did not verify")
            report = {"scan_id": str(scan_id)}
            if knowledge_executor:
                report["operation_id"] = state["report"]["operation_id"]
            return {"status": "report_verified" if knowledge_executor else "finished", "errors": [], "report": report}
        except Exception:
            return {"status": "unknown", "errors": ["stored scan or report could not be verified"], "report": {}}

    def knowledge(state):
        try:
            workflow_id, digest = _request(state)
            scan_id = UUID(state["report"]["scan_id"])
            claim = lookup_stage(engine, workflow_id=workflow_id, stage="knowledge_context", input_digest=digest)
            if claim is None:
                if reconcile_only:
                    return {"status": "unknown", "errors": ["knowledge stage has not completed"], "report": {}}
                if knowledge_prepare is not None:
                    knowledge_prepare(state)
                if _request(state) != (workflow_id, digest):
                    raise ValueError("workflow request changed")
                claim = claim_stage(engine, workflow_id=workflow_id, stage="knowledge_context", input_digest=digest)
            if claim.status == "unknown":
                return {"status": "unknown", "errors": ["knowledge stage requires reconciliation"], "report": {}}
            manifest_id = claim.result_id
            if claim.status == "claimed":
                if _request(state) != (workflow_id, digest):
                    raise ValueError("workflow request changed")
                manifest_id = knowledge_executor(state, claim.operation_id, claim.owner_token, digest, scan_id)
            if not isinstance(manifest_id, UUID) or knowledge_verifier(
                    state, claim.operation_id, manifest_id, digest, scan_id) is not True:
                raise ValueError("knowledge stage receipt could not be verified")
            return {"status": "knowledge_recorded", "errors": [], "report": {
                "scan_id": str(scan_id), "operation_id": state["report"]["operation_id"]}}
        except Exception:
            return {"status": "unknown", "errors": ["knowledge stage could not be confirmed"], "report": {}}

    def verify_final_report(state):
        # The local knowledge stage may be slow, so re-read the report and
        # authorization at the end rather than relying on the earlier check.
        result = verify_report(state)
        if result["status"] == "report_verified":
            result["status"] = "finished"
            result["report"].pop("operation_id", None)
        return result

    def plan(state):
        try:
            from vulnmind.agents.tool_plan import ALLOWED
            from vulnmind.persistence.workflow_plans import load_tool_plan
            workflow_id, digest = _request(state)
            configured = state.get("workflow_options", {}).get("tools")
            if not isinstance(configured, list) or any(not isinstance(item, str) for item in configured):
                raise ValueError("invalid enabled tools")
            enabled = set(configured) - {"python_tls"}
            if not enabled or not enabled <= ALLOWED or len(configured) != len(set(configured)):
                raise ValueError("invalid enabled tools")
            # Previously started scans, including legacy workflows, must never
            # cause a new planner call just because no plan receipt exists.
            existing_scan = lookup_stage(engine, workflow_id=workflow_id, stage="repository_scan", input_digest=digest)
            if existing_scan is not None:
                prior_plan = lookup_stage(engine, workflow_id=workflow_id, stage="repository_plan", input_digest=digest)
                if prior_plan is not None:
                    if prior_plan.status != "completed":
                        return {"status": "unknown", "errors": ["prior planning requires reconciliation"], "plan": {}}
                    try:
                        load_tool_plan(engine, plan_id=prior_plan.result_id, operation_id=prior_plan.operation_id,
                                       enabled=enabled)
                    except Exception:
                        return {"status": "unknown", "errors": ["stored workflow plan could not be verified"], "plan": {}}
                return {"status": "planned", "plan": {"prior_scan": True}, "errors": []}
            claim = lookup_stage(engine, workflow_id=workflow_id, stage="repository_plan", input_digest=digest)
            if claim is None:
                if plan_prepare is not None:
                    try:
                        plan_prepare(state)
                    except Exception:
                        return {"status": "blocked", "errors": ["workflow planner is unavailable"], "plan": {}}
                claim = claim_stage(engine, workflow_id=workflow_id, stage="repository_plan", input_digest=digest)
            if claim.status == "unknown":
                return {"status": "unknown", "errors": ["prior planning requires reconciliation"], "plan": {}}
        except ValueError:
            return {"status": "blocked", "errors": ["workflow plan could not be validated"], "plan": {}}
        except Exception:
            return {"status": "unknown", "errors": ["workflow plan outcome is uncertain"], "plan": {}}
        try:
            plan_id = claim.result_id
            if claim.status == "claimed":
                plan_id = plan_executor(state, claim.operation_id, claim.owner_token, digest, enabled)
            selected = load_tool_plan(engine, plan_id=plan_id, operation_id=claim.operation_id, enabled=enabled)
            return {"status": "planned", "plan": {"selected_tools": list(selected)}, "errors": []}
        except Exception:
            return {"status": "unknown", "errors": ["workflow plan outcome is uncertain"], "plan": {}}

    graph = StateGraph(VulnMindState)
    graph.add_node("authorize", scope)
    graph.add_node("repository_scan", execute)
    if plan_executor is not None and not reconcile_only:
        graph.add_node("repository_plan", plan)
        graph.add_conditional_edges("repository_plan", lambda state: state["status"] == "planned",
                                    {True: "repository_scan", False: END})
    graph.add_edge(START, "authorize")
    graph.add_conditional_edges("authorize", lambda state: state["status"] == "authorized", {
        True: "repository_plan" if plan_executor is not None and not reconcile_only else "repository_scan",
        False: END})
    if report_verifier is not None:
        graph.add_node("verify_report", verify_report)
        graph.add_conditional_edges("repository_scan", lambda state: state["status"] == "scan_recorded",
                                    {True: "verify_report", False: END})
        if knowledge_executor is not None:
            graph.add_node("knowledge_context", knowledge)
            graph.add_conditional_edges("verify_report", lambda state: state["status"] == "report_verified",
                                        {True: "knowledge_context", False: END})
            graph.add_node("verify_final_report", verify_final_report)
            graph.add_conditional_edges("knowledge_context", lambda state: state["status"] == "knowledge_recorded",
                                        {True: "verify_final_report", False: END})
            graph.add_edge("verify_final_report", END)
        else:
            graph.add_edge("verify_report", END)
    else:
        graph.add_edge("repository_scan", END)
    return graph.compile(checkpointer=checkpointer)
