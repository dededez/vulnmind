"""Knowledge documents/chunks, skills, three-level memory and context manifests.

Dense vectors (pgvector) are added by a later revision once the deployment
provides the ``vector`` server extension; this revision keeps the sparse
PostgreSQL full-text column so retrieval storage is usable without it.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR

revision = "0003_knowledge_memory"
down_revision = "0002_execution_records"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("knowledge_documents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_url", sa.Text()),
        sa.Column("version", sa.String(64)),
        sa.Column("trust_level", sa.String(32)),
        sa.Column("metadata", JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("knowledge_chunks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("document_id", sa.Uuid(), sa.ForeignKey("knowledge_documents.id"), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("tsvector", TSVECTOR()),
        sa.Column("metadata", JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("document_id", "chunk_index", name="uq_knowledge_chunks_document_chunk"),
        sa.Index("ix_knowledge_chunks_document_id", "document_id"),
        sa.Index("ix_knowledge_chunks_tsvector", "tsvector", postgresql_using="gin"))
    op.create_table("skills",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32)),
        sa.Column("vuln_type", sa.String(128)),
        sa.Column("stage", sa.String(64)),
        sa.Column("content_uri", sa.Text(), nullable=False),
        sa.Column("metadata", JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("name", "version", name="uq_skills_name_version"))
    op.create_table("memory_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("task_id", sa.Uuid(), sa.ForeignKey("scan_tasks.id")),
        sa.Column("memory_type", sa.String(64)),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source_refs", JSONB(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("validated_by", sa.String(255)),
        sa.Column("invalidated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("level IN ('short_term', 'working', 'long_term')", name="ck_memory_records_level"),
        sa.Index("ix_memory_records_project_task", "project_id", "task_id"))
    op.create_table("context_manifests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("agent_runs.id"), nullable=False),
        sa.Column("agent_name", sa.String(128), nullable=False),
        sa.Column("selected_refs", JSONB(), nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    for name in ("context_manifests", "memory_records", "skills", "knowledge_chunks", "knowledge_documents"):
        op.drop_table(name)
