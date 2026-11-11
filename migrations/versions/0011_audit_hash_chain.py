"""Add a tamper-evident hash chain to audit_events.

Legacy rows keep NULL hashes and are reported as unhashed; new rows link to the
latest hashed row. This detects accidental or naive modification, not an
attacker who can rewrite the whole table and its hashes.
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_audit_hash_chain"
down_revision = "0010_web_endpoints"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("audit_events", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_events", sa.Column("entry_hash", sa.String(64), nullable=True))


def downgrade():
    op.drop_column("audit_events", "entry_hash")
    op.drop_column("audit_events", "prev_hash")
