"""Enforce one finding per scan and fingerprint.

Existing duplicates make this migration fail: inspect and resolve them
explicitly before retrying; this migration does not delete or merge data.
"""
from alembic import op

revision = "0006_finding_identity"
down_revision = "0005_approval_binding"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint("uq_findings_scan_fingerprint", "findings", ["scan_id", "fingerprint"])


def downgrade():
    op.drop_constraint("uq_findings_scan_fingerprint", "findings", type_="unique")
