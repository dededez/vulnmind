"""Backfill sparse vectors and keep them consistent with stored content.

This update may lock many knowledge rows; review and schedule it before use on
an existing database. It does not delete or merge documents.
"""
from alembic import op

revision = "0008_knowledge_fts_consistency"
down_revision = "0007_finding_observations"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE knowledge_chunks SET tsvector = pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, content) WHERE tsvector IS DISTINCT FROM pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, content)")
    op.execute("""CREATE FUNCTION vulnmind_knowledge_tsvector_sync() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            NEW.tsvector := pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, NEW.content);
            RETURN NEW;
        END;
        $$""")
    op.execute("""CREATE TRIGGER vulnmind_knowledge_tsvector_sync
        BEFORE INSERT OR UPDATE ON knowledge_chunks
        FOR EACH ROW EXECUTE FUNCTION vulnmind_knowledge_tsvector_sync()""")


def downgrade():
    op.execute("DROP TRIGGER vulnmind_knowledge_tsvector_sync ON knowledge_chunks")
    op.execute("DROP FUNCTION vulnmind_knowledge_tsvector_sync()")
