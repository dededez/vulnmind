"""Persist committed selections of the single-attempt workflow planner."""
import sqlalchemy as sa
from alembic import op

revision = "0016_workflow_tool_plans"
down_revision = "0015_workflow_operations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workflow_tool_plans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("operation_id", sa.Uuid(), sa.ForeignKey("workflow_operations.id"), nullable=False),
        sa.Column("selected_tools", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("operation_id", name="uq_workflow_tool_plan_operation"),
    )


def downgrade():
    # An unfinished plan claim also prevents a safe downgrade: older code
    # does not know about it and could send the model request again. Lock in
    # the same table order as the planning transaction (operation, then plan).
    op.execute("LOCK TABLE workflow_operations, workflow_tool_plans IN ACCESS EXCLUSIVE MODE")
    bind = op.get_bind()
    if (bind.execute(sa.text("SELECT count(*) FROM workflow_tool_plans")).scalar_one()
            or bind.execute(sa.text("SELECT count(*) FROM workflow_operations WHERE stage = 'repository_plan'")).scalar_one()):
        raise RuntimeError("refusing to discard workflow tool plans or planning claims")
    op.drop_table("workflow_tool_plans")
