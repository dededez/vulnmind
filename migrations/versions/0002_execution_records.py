"""Execution, findings, evidence, approvals and append-only audit event records."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002_execution_records"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("scan_tasks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("parent_id", sa.Uuid(), sa.ForeignKey("scan_tasks.id")),
        sa.Column("phase", sa.String(64), nullable=False), sa.Column("agent_name", sa.String(128)),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("scope", JSONB()), sa.Column("acceptance", JSONB()))
    op.create_table("agent_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("task_id", sa.Uuid(), sa.ForeignKey("scan_tasks.id"), nullable=False),
        sa.Column("agent_name", sa.String(128), nullable=False), sa.Column("model", sa.String(255)),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("input_ref", sa.Text()),
        sa.Column("output_ref", sa.Text()), sa.Column("usage", JSONB()))
    op.create_table("tool_invocations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("agent_runs.id"), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False), sa.Column("args_hash", sa.String(64)),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("exit_code", sa.Integer()),
        sa.Column("duration", sa.Float()), sa.Column("output_ref", sa.Text()))
    op.create_table("findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False), sa.Column("title", sa.Text(), nullable=False),
        sa.Column("vuln_type", sa.String(128), nullable=False), sa.Column("severity", sa.String(32)),
        sa.Column("confidence", sa.String(32)), sa.Column("status", sa.String(32), nullable=False), sa.Column("location", JSONB()))
    op.create_table("evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("evidence_type", sa.String(64), nullable=False), sa.Column("locator", sa.Text()),
        sa.Column("content_ref", sa.Text(), nullable=False), sa.Column("hash", sa.String(128)),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("format", sa.String(32), nullable=False), sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("approvals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("action", sa.String(255), nullable=False), sa.Column("target", sa.Text(), nullable=False),
        sa.Column("approver", sa.String(255)), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)))
    op.create_table("audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("call_id", sa.Uuid(), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False), sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("args_hash", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    for name in ("audit_events", "approvals", "reports", "evidence", "findings", "tool_invocations", "agent_runs", "scan_tasks"):
        op.drop_table(name)
