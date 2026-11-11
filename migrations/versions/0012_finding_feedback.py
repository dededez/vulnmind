"""Add append-only operator feedback per finding.

A row records what an operator decided (false positive, confirmed, accepted
risk, needs more information). It is not a verification result and does not
change the generator's triage status; the label is rendered next to the finding
and can suppress the open-validation count. ``(finding_id, revision)`` is unique
so concurrent writers cannot silently overwrite each other's decision.
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_finding_feedback"
down_revision = "0011_audit_hash_chain"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "finding_feedback",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("finding_id", "revision", name="uq_finding_feedback_revision"),
        sa.CheckConstraint(
            "verdict IN ('false_positive', 'confirmed', 'accepted_risk', 'needs_more_info')",
            name="ck_finding_feedback_verdict"),
    )
    op.create_index("ix_finding_feedback_scan", "finding_feedback", ["scan_id", "created_at"])


def downgrade():
    op.drop_index("ix_finding_feedback_scan", table_name="finding_feedback")
    op.drop_table("finding_feedback")
