"""Persist observed form parameter names; NULL means not recorded."""
from alembic import op
import sqlalchemy as sa

revision = "0013_endpoint_parameters"
down_revision = "0012_finding_feedback"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("web_endpoints", sa.Column("parameters", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("web_endpoints", "parameters")
