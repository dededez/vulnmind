"""Initial business records; remaining design tables are future migrations."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("projects", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(255), nullable=False), sa.Column("description", sa.Text()), sa.Column("tech_stack", postgresql.JSONB()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("targets", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False), sa.Column("target_type", sa.String(32), nullable=False), sa.Column("locator", sa.Text(), nullable=False), sa.Column("metadata", postgresql.JSONB()))
    op.create_table("scopes", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id"), nullable=False), sa.Column("allowlist", postgresql.JSONB(), nullable=False), sa.Column("denylist", postgresql.JSONB()), sa.Column("rate_limit", postgresql.JSONB()), sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("approved_by", sa.String(255), nullable=False), sa.Column("authorization_source", sa.Text(), nullable=False))
    op.create_table("scans", sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("mode", sa.String(32), nullable=False), sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)))


def downgrade():
    for name in ("scans", "scopes", "targets", "projects"):
        op.drop_table(name)
