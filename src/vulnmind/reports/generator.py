"""Deterministic Markdown/JSON reports from grouped finding candidates.

The generator renders source claims without independently verifying them and
keeps the explicit "not scanned" banner for simulation runs. A nonempty
evidence reference alone does not establish that the evidence exists.
"""
from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnmind.findings import FindingGroup
from vulnmind.knowledge.answer import GroundedAnswer
from vulnmind.reports.evidence_snapshot import MAX_SNAPSHOT_IDS

SCHEMA_VERSION = 7
_SIMULATION_BANNER = ("> 注意：本报告来自模拟流程，未执行真实扫描、HTTP 请求或 Shell 命令；"
                      "其中的发现要么为空，要么是明确标注的占位数据。")
_FEEDBACK_LABELS = {"false_positive": "误报", "confirmed": "确认",
                    "accepted_risk": "接受风险", "needs_more_info": "需要更多信息"}


class DecisionSummary(BaseModel):
    """Triage result reduced to what a report may state without new claims."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=1, max_length=128)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    confidence: float = Field(ge=0, le=1)
    requires_validation: bool = True
    rationale: tuple[str, ...] = ()


class AgentReviewItem(BaseModel):
    """One advisory model opinion; never a verification result."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=1, max_length=128)
    verdict: Literal["confirmed", "likely", "false_positive"]
    rationale: str = Field(min_length=1, max_length=500)
    note: str | None = Field(default=None, max_length=300)


class AgentReviewSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["completed", "failed", "skipped"]
    summary: str = Field(default="", max_length=1000)
    ignored: int = Field(default=0, ge=0)
    items: tuple[AgentReviewItem, ...] = ()
    total_groups: int | None = Field(default=None, ge=0)
    selected_groups: int | None = Field(default=None, ge=0)
    omitted_groups: int | None = Field(default=None, ge=0)
    groups_without_verdict: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def consistent_coverage(self):
        values = (self.total_groups, self.selected_groups, self.omitted_groups, self.groups_without_verdict)
        if all(value is None for value in values):
            return self
        if any(value is None for value in values):
            raise ValueError("review coverage counts must be supplied together")
        if (self.selected_groups + self.omitted_groups != self.total_groups
                or self.groups_without_verdict + len(self.items) != self.selected_groups):
            raise ValueError("review coverage counts are inconsistent")
        return self


class FeedbackSummary(BaseModel):
    """One operator-recorded verdict; never an automated verification result."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=1, max_length=128)
    verdict: Literal["false_positive", "confirmed", "accepted_risk", "needs_more_info"]
    actor: str = Field(min_length=1, max_length=255)
    note: str | None = Field(default=None, max_length=2000)
    recorded_at: datetime
    revision: int = Field(ge=1)

    @field_validator("recorded_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("feedback timestamp must be timezone-aware")
        return value


class ReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    mode: Literal["simulation", "analysis"]
    groups: list[FindingGroup] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    limitations: list[str] = Field(default_factory=list)
    decisions: list[DecisionSummary] = Field(default_factory=list)
    agent_review: AgentReviewSummary | None = None
    knowledge_review: GroundedAnswer | None = None
    evidence_record_ids: dict[str, list[UUID]] = Field(default_factory=dict)
    evidence_snapshot: Literal["unavailable", "available"] = "unavailable"
    evidence_snapshot_truncated: bool = False
    feedback: tuple[FeedbackSummary, ...] = ()

    @model_validator(mode="after")
    def valid_feedback(self):
        fingerprints = [item.fingerprint for item in self.feedback]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("feedback must have at most one verdict per finding")
        if set(fingerprints) - {group.fingerprint for group in self.groups}:
            raise ValueError("feedback must belong to a reported group")
        return self

    @model_validator(mode="after")
    def valid_evidence_snapshot(self):
        if self.evidence_snapshot == "unavailable" and (self.evidence_record_ids or self.evidence_snapshot_truncated):
            raise ValueError("unavailable evidence snapshot cannot contain records")
        if set(self.evidence_record_ids) - {group.fingerprint for group in self.groups}:
            raise ValueError("evidence record must belong to a reported group")
        ids = [item for values in self.evidence_record_ids.values() for item in values]
        if len(ids) > MAX_SNAPSHOT_IDS or len(ids) != len(set(ids)):
            raise ValueError("evidence record IDs must be unique and within the limit")
        return self

    @field_validator("groups", mode="before")
    @classmethod
    def revalidate_groups(cls, value):
        if isinstance(value, list):
            return [FindingGroup.model_validate(item.model_dump() if isinstance(item, FindingGroup) else item) for item in value]
        return value

    @field_validator("scan_id", "project_id")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scan and project identifiers cannot be blank")
        return value

    @field_validator("generated_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("report timestamp must be timezone-aware")
        return value


class ReportDocument(BaseModel):
    model_config = ConfigDict(frozen=True)
    format: Literal["markdown", "json"]
    content: str
    sha256: str
    counts: dict[str, int]


def generate(report: ReportInput, *, format: Literal["markdown", "json"] = "markdown") -> ReportDocument:
    if format == "markdown":
        content = render_markdown(report)
    elif format == "json":
        content = json.dumps(render_json(report), ensure_ascii=False, indent=2, sort_keys=True)
    else:
        raise ValueError("unsupported report format")
    return ReportDocument(format=format, content=content,
                          sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                          counts=count_by_status(report.groups))


def count_by_status(groups: list[FindingGroup]) -> dict[str, int]:
    counts = {"unverified": 0, "confirmed": 0, "not_reproduced": 0, "insufficient_evidence": 0}
    for group in groups:
        group = FindingGroup.model_validate(group.model_dump())
        for candidate in group.candidates:
            counts[candidate.status] += 1
    return counts


def render_json(report: ReportInput) -> dict:
    report = ReportInput.model_validate(report.model_dump())
    feedback = sorted(report.feedback, key=lambda item: item.fingerprint)
    resolved = {item.fingerprint for item in feedback if item.verdict != "needs_more_info"}
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": report.scan_id,
        "project_id": report.project_id,
        "mode": report.mode,
        "generated_at": report.generated_at.isoformat(),
        "not_scanned": report.mode == "simulation",
        "validation_performed": False,
        "status_interpretation": "source_claim_not_independently_verified",
        "evidence_snapshot": report.evidence_snapshot,
        "evidence_snapshot_truncated": report.evidence_snapshot_truncated,
        "evidence_snapshot_interpretation": "transaction_snapshot_not_integrity_or_vulnerability_verification",
        "counts": count_by_status(report.groups),
        "validation_required": sum(1 for item in report.decisions if item.requires_validation),
        "open_validation_required": sum(1 for item in report.decisions
                                        if item.requires_validation and item.fingerprint not in resolved),
        "decisions": [{
            "fingerprint": item.fingerprint, "severity": item.severity,
            "confidence": item.confidence, "requires_validation": item.requires_validation,
            "rationale": list(item.rationale),
        } for item in report.decisions],
        "agent_review": _agent_review_json(report.agent_review),
        **({"knowledge_review": report.knowledge_review.model_dump(mode="json")}
           if report.knowledge_review is not None else {}),
        "feedback": [{
            "fingerprint": item.fingerprint, "verdict": item.verdict, "actor": item.actor,
            "note": item.note, "revision": item.revision,
            "recorded_at": item.recorded_at.isoformat(),
        } for item in feedback],
        "feedback_interpretation": "operator_recorded_decision_not_verification",
        "groups": [{
            "fingerprint": group.fingerprint,
            "titles": list(dict.fromkeys(candidate.title for candidate in group.candidates)),
            "vulnerability_types": list(dict.fromkeys(candidate.vulnerability_type for candidate in group.candidates)),
            "statuses": list(dict.fromkeys(candidate.status for candidate in group.candidates)),
            "severities": list(dict.fromkeys(candidate.severity for candidate in group.candidates
                                             if candidate.severity is not None)),
            "source_tools": group.source_tools,
            "evidence_refs": group.evidence_refs,
            "stored_evidence_ids": [str(item) for item in report.evidence_record_ids.get(group.fingerprint, [])],
            "candidates": [{
                "title": candidate.title, "vulnerability_type": candidate.vulnerability_type,
                "target_id": candidate.target_id, "location": candidate.location,
                "source_tool": candidate.source_tool, "status": candidate.status,
                "severity": candidate.severity,
                "evidence_refs": list(candidate.evidence_refs),
            } for candidate in group.candidates],
        } for group in report.groups],
        "limitations": list(report.limitations),
    }


def _agent_review_json(review: AgentReviewSummary | None) -> dict | None:
    if review is None:
        return None
    return {
        "status": review.status,
        "summary": review.summary,
        "ignored": review.ignored,
        "total_groups": review.total_groups,
        "selected_groups": review.selected_groups,
        "omitted_groups": review.omitted_groups,
        "groups_without_verdict": review.groups_without_verdict,
        "interpretation": "advisory_model_review_not_verification",
        "items": [{"fingerprint": item.fingerprint, "verdict": item.verdict,
                   "rationale": item.rationale, "note": item.note} for item in review.items],
    }


def render_markdown(report: ReportInput) -> str:
    report = ReportInput.model_validate(report.model_dump())
    counts = count_by_status(report.groups)
    lines = ["# VulnMind 报告", "",
             f"- 扫描：{_text(report.scan_id)}",
             f"- 项目：{_text(report.project_id)}",
             f"- 模式：{'模拟' if report.mode == 'simulation' else '分析'}",
             f"- 生成时间：{report.generated_at.isoformat()}"]
    if report.mode == "simulation":
        lines += ["", _SIMULATION_BANNER]
    lines += ["", "> 发现状态为输入来源的声明，系统尚未独立验证证据或结论。"]
    if report.evidence_snapshot == "unavailable":
        lines.append("> 未读取持久化证据记录；不得据此判断是否存在证据。")
    else:
        lines.append("> 证据 ID 表示生成报告时的数据库事务快照，可能尚未提交；未核验文件完整性、来源或漏洞结论。")
    if report.evidence_snapshot_truncated:
        lines.append("> 证据记录清单已截断，未列出全部记录。")
    decisions = {item.fingerprint: item for item in report.decisions}
    feedback = {item.fingerprint: item for item in report.feedback}
    resolved = {item.fingerprint for item in report.feedback if item.verdict != "needs_more_info"}
    lines += ["", "## 摘要", "",
              f"- 分组数：{len(report.groups)}",
              "- 候选状态（来源声明）：" + "，".join(f"{name}={value}" for name, value in counts.items())]
    if report.decisions:
        pending = sum(1 for item in report.decisions if item.requires_validation)
        lines.append(f"- 需要人工验证的分组：{pending}")
        lines.append(f"- 排除已记录人工判定后的待验证分组："
                     f"{sum(1 for item in report.decisions if item.requires_validation and item.fingerprint not in resolved)}")
    if report.feedback:
        lines.append(f"- 已记录人工判定：{len(report.feedback)}（其中误报 "
                     f"{sum(1 for item in report.feedback if item.verdict == 'false_positive')}）")
        lines.append("> 人工判定是操作者的记录，不是系统的漏洞验证结论。")
    if not report.groups:
        lines += ["", "本次运行没有产生任何发现候选。没有发现不等于不存在漏洞，也不等于扫描已完成。"]
    else:
        lines += ["", "## 发现"]
        for index, group in enumerate(report.groups, start=1):
            candidates = group.candidates
            title = candidates[0].title
            lines += ["", f"### {index}. {_text(title)}", "",
                      f"- 漏洞类型：{_text(candidates[0].vulnerability_type)}",
                      f"- 状态：{'，'.join(dict.fromkeys(candidate.status for candidate in candidates))}",
                      f"- 风险：{'，'.join(dict.fromkeys(candidate.severity for candidate in candidates if candidate.severity)) or '未评定'}",
                      f"- 来源工具：{'，'.join(_text(source) for source in group.source_tools)}",
                      f"- 指纹：{_text(group.fingerprint)}"]
            decision = decisions.get(group.fingerprint)
            if decision is not None:
                lines.append(f"- 置信度：{decision.confidence:.2f}（需人工验证：{'是' if decision.requires_validation else '否'}）")
            recorded = feedback.get(group.fingerprint)
            if recorded is not None:
                lines.append(f"- 人工判定：{_FEEDBACK_LABELS[recorded.verdict]}"
                             f"（{_text(recorded.actor)} 于 {recorded.recorded_at.isoformat()}，操作者记录）")
            for candidate in candidates:
                lines.append(f"- 位置：{_text(candidate.target_id)} @ { _text(candidate.location) }"
                             f"（状态 {candidate.status}）")
            if group.evidence_refs:
                lines.append(f"- 证据引用（未核验）：{'，'.join(_text(ref) for ref in group.evidence_refs)}")
            else:
                lines.append("- 来源声明的证据引用：无")
            if report.evidence_snapshot == "available":
                ids = report.evidence_record_ids.get(group.fingerprint, [])
                lines.append("- 持久化证据记录 ID（未核验）：" + ("，".join(str(item) for item in ids) if ids else "本清单未列出"))
    if report.feedback:
        lines += ["", "## 人工复核记录（操作者判定，未自动验证）", ""]
        for item in sorted(report.feedback, key=lambda value: value.fingerprint):
            note = f"；备注：{_text(item.note)}" if item.note else ""
            lines.append(f"- {_text(item.fingerprint[:16])}…：{_FEEDBACK_LABELS[item.verdict]}"
                         f"（{_text(item.actor)} @ {item.recorded_at.isoformat()}，第 {item.revision} 次记录{note}）")
        lines.append("> 该判定只表示操作者的处理结论，未改变来源状态，也不代表漏洞已被确认或已排除。")
    if report.agent_review is not None:
        lines += ["", "## 模型复核（建议，未验证）", ""]
        review = report.agent_review
        if review.total_groups is not None:
            lines.append(f"- 覆盖范围：共 {review.total_groups} 组，选入 {review.selected_groups} 组，"
                         f"未选入 {review.omitted_groups} 组；选入但无判定 {review.groups_without_verdict} 组")
        if review.status != "completed":
            lines.append(f"- 复核状态：{_text(review.status)}；扫描保留确定性结果")
        else:
            lines.append(f"- 摘要：{_text(review.summary)}")
            if review.ignored:
                lines.append(f"- 已忽略的模型条目：{review.ignored}")
            for item in review.items:
                note = f"（{_text(item.note)}）" if item.note else ""
                lines.append(f"- {_text(item.fingerprint[:16])}…：{item.verdict} — {_text(item.rationale)}{note}")
        lines.append("> 上述判定由模型生成，不构成验证；候选状态与严重度仍以确定性 Triage 为准。")
    if report.knowledge_review is not None:
        knowledge = report.knowledge_review
        lines += ["", "## 知识辅助建议（未验证）", "", f"- 状态：{_text(knowledge.status)}",
                  f"- 支持性模型审核：{_text(knowledge.review_status)}（不构成事实验证）"]
        if knowledge.answer:
            lines.append(f"- 建议：{_text(knowledge.answer)}")
        for reference in knowledge.references:
            lines.append(f"- 引用：{_text(reference.ref)}；文档 {_text(reference.document_id)}；"
                         f"片段 {_text(reference.chunk_id)}；SHA-256 {_text(reference.sha256)}；"
                         f"模型引用：{reference.cited}")
    if report.limitations:
        lines += ["", "## 限制", ""] + [f"- {_text(item)}" for item in report.limitations]
    return "\n".join(lines) + "\n"


def _text(value: str) -> str:
    # Keep one line per field and neutralise the characters that would break a
    # Markdown table or start a link in a downloaded report.
    cleaned = html.escape(" ".join(str(value).split()), quote=True)
    for character in ("\\", "`", "[", "]", "|", "*", "_"):
        cleaned = cleaned.replace(character, "\\" + character)
    return cleaned
