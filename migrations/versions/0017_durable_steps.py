"""Atomic receipts for recoverable repository and HTTP stages."""
import sqlalchemy as sa
from alembic import op

revision = "0017_durable_steps"
down_revision = "0016_workflow_tool_plans"
branch_labels = depends_on = None


def upgrade():
    op.create_table("durable_steps",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON()),
        sa.Column("output_digest", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("workflow_id", "stage", name="uq_durable_step"),
        sa.CheckConstraint("status IN ('ready', 'running', 'completed', 'aborted')", name="ck_durable_step_status"),
        sa.CheckConstraint("attempt >= 1", name="ck_durable_step_attempt"),
        sa.CheckConstraint("(status = 'completed' AND payload IS NOT NULL AND output_digest IS NOT NULL) OR "
                           "(status != 'completed' AND output_digest IS NULL)", name="ck_durable_step_receipt"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT count(*) FROM durable_steps")).scalar_one():
        raise RuntimeError("refusing to discard recovery history")
    op.drop_table("durable_steps")
