"""Add the pgvector embedding column and its index to knowledge_chunks.

Requires the ``vector`` server extension (built separately into the PostgreSQL
installation). The migration fails loudly when the extension is missing instead
of silently skipping the column, because a "successful" migration without the
column would make dense retrieval look available when it is not.
"""
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

# Frozen historical dimension: this revision created the placeholder column at
# 1536. It must not follow vulnmind.knowledge.vector.EMBEDDING_DIMENSIONS,
# otherwise editing that constant would silently rewrite history; migration
# 0014 is the revision that resizes the column.
_PLACEHOLDER_DIMENSIONS = 1536

revision = "0009_pgvector_embedding"
down_revision = "0008_knowledge_fts_consistency"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.add_column("knowledge_chunks",
                  sa.Column("embedding", Vector(_PLACEHOLDER_DIMENSIONS), nullable=True))
    # HNSW needs no training data, unlike ivfflat; cosine matches normalised
    # embeddings and the RRF fusion stage that sits above it.
    op.create_index("ix_knowledge_chunks_embedding_hnsw", "knowledge_chunks", ["embedding"],
                    postgresql_using="hnsw", postgresql_ops={"embedding": "vector_cosine_ops"})


def downgrade():
    op.drop_index("ix_knowledge_chunks_embedding_hnsw", table_name="knowledge_chunks")
    op.drop_column("knowledge_chunks", "embedding")
