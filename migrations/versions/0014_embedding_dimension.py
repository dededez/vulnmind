"""Resize the pgvector column to the chosen embedding model's dimension.

Migration 0009 created the placeholder column at 1536 dimensions. The project
now embeds knowledge with Qwen3-Embedding-0.6B, which emits 1024-dimensional
vectors. Dense retrieval was never enabled, so no vectors are stored yet and
the column can be resized without losing data; the migration refuses to run if
a vector exists rather than silently discarding it.

Migration 0009 keeps its historical 1536 as a frozen literal, so it continues
to describe what it actually did; this revision is the only place that changes
the active dimension.
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_embedding_dimension"
down_revision = "0013_endpoint_parameters"
branch_labels = None
depends_on = None

_OLD_DIMENSION = 1536
_NEW_DIMENSION = 1024
_INDEX = "ix_knowledge_chunks_embedding_hnsw"


def _require_no_vectors() -> None:
    # Prevent a writer from inserting a vector between the check and ALTER.
    op.execute("LOCK TABLE knowledge_chunks IN ACCESS EXCLUSIVE MODE")
    stored = op.get_bind().execute(
        sa.text("SELECT count(*) FROM knowledge_chunks WHERE embedding IS NOT NULL")).scalar_one()
    if stored:
        raise RuntimeError(
            "refusing to resize the embedding column while vectors are stored; "
            "clear or re-embed them first")


def _resize(dimension: int) -> None:
    op.drop_index(_INDEX, table_name="knowledge_chunks")
    # pgvector has no cross-dimension cast; every stored value is NULL here.
    op.execute(f"ALTER TABLE knowledge_chunks ALTER COLUMN embedding TYPE vector({dimension}) USING NULL")
    op.create_index(_INDEX, "knowledge_chunks", ["embedding"],
                    postgresql_using="hnsw", postgresql_ops={"embedding": "vector_cosine_ops"})


def upgrade() -> None:
    _require_no_vectors()
    _resize(_NEW_DIMENSION)


def downgrade() -> None:
    # Re-embedding requires an explicit, separately reviewed data operation.
    _require_no_vectors()
    _resize(_OLD_DIMENSION)
