"""Record single-attempt workflow operations for conservative recovery."""
import sqlalchemy as sa
from alembic import op

revision = "0015_workflow_operations"
down_revision = "0014_embedding_dimension"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workflow_operations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("owner_token", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result_ref", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("workflow_id", "stage", name="uq_workflow_operation_stage"),
        sa.CheckConstraint("status IN ('started', 'completed')", name="ck_workflow_operation_status"),
        sa.CheckConstraint("(status = 'started' AND result_ref IS NULL) OR "
                           "(status = 'completed' AND result_ref IS NOT NULL)",
                           name="ck_workflow_operation_result"),
    )


def downgrade():
    # Prevent loss of claims which are needed to avoid replay after recovery.
    op.execute("LOCK TABLE workflow_operations IN ACCESS EXCLUSIVE MODE")
    if op.get_bind().execute(sa.text("SELECT count(*) FROM workflow_operations")).scalar_one():
        raise RuntimeError("refusing to discard workflow operation history")
    op.drop_table("workflow_operations")
