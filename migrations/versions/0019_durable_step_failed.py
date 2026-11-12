"""Allow durable stages to be marked failed instead of looking in-flight."""
import sqlalchemy as sa
from alembic import op

revision = '0019_durable_step_failed'
down_revision = '0018_workbench_jobs'
branch_labels = depends_on = None

ALLOWED = "status IN ('ready', 'running', 'completed', 'aborted', 'failed')"
LEGACY = "status IN ('ready', 'running', 'completed', 'aborted')"


def upgrade():
    with op.batch_alter_table('durable_steps') as batch:
        batch.drop_constraint('ck_durable_step_status', type_='check')
        batch.create_check_constraint('ck_durable_step_status', ALLOWED)


def downgrade():
    op.get_bind().execute(sa.text("UPDATE durable_steps SET status='aborted' WHERE status='failed'"))
    with op.batch_alter_table('durable_steps') as batch:
        batch.drop_constraint('ck_durable_step_status', type_='check')
        batch.create_check_constraint('ck_durable_step_status', LEGACY)
