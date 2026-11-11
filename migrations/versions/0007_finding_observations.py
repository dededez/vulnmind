"""Retain independent source claims without asserting evidence verification."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_finding_observations"
down_revision = "0006_finding_identity"
branch_labels = None
depends_on = None


def upgrade():
    # Existing summaries predate observation history and require review.
    op.add_column("findings", sa.Column("needs_retriage", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("findings", sa.Column("observation_revision", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("findings", sa.Column("observation_history_complete", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table("finding_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("observation_hash", sa.String(64), nullable=False),
        sa.Column("source_tool", sa.String(255), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("source_status_claim", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(32)),
        sa.Column("evidence_refs", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("finding_id", "observation_hash", name="uq_finding_observation_identity"))


def downgrade():
    op.drop_table("finding_observations")
    op.drop_column("findings", "observation_history_complete")
    op.drop_column("findings", "observation_revision")
    op.drop_column("findings", "needs_retriage")
