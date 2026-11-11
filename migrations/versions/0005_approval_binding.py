"""Bind approvals to a specific operation and support atomic consumption."""
from alembic import op
import sqlalchemy as sa

revision = "0005_approval_binding"
down_revision = "0004_approval_expiry"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("approvals", sa.Column("operation_hash", sa.String(64), nullable=True))
    op.add_column("approvals", sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("approvals", "consumed_at")
    op.drop_column("approvals", "operation_hash")
