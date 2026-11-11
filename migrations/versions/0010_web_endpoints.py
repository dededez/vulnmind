"""Add web_endpoints so crawl discoveries can be stored and reviewed.

Rows are observations from an authorized crawl; nothing here asserts that an
endpoint is reachable or vulnerable. The unique constraint makes re-running a
crawl for the same scan idempotent at the database level as well.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_web_endpoints"
down_revision = "0009_pgvector_embedding"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "web_endpoints",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("scan_id", "method", "url", name="uq_web_endpoints_scan_method_url"),
    )
    op.create_index("ix_web_endpoints_scan_id", "web_endpoints", ["scan_id"])


def downgrade():
    op.drop_index("ix_web_endpoints_scan_id", table_name="web_endpoints")
    op.drop_table("web_endpoints")
