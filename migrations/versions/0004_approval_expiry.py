"""Approvals expire so a stale decision cannot unlock a later action."""
from alembic import op
import sqlalchemy as sa

revision = "0004_approval_expiry"
down_revision = "0003_knowledge_memory"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("approvals", sa.Column("expires_at", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("approvals", "expires_at")
