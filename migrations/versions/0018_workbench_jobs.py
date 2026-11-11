"""Local unified workbench jobs; execution receipts remain in durable_steps."""
import sqlalchemy as sa
from alembic import op
revision='0018_workbench_jobs'
down_revision='0017_durable_steps'
branch_labels=depends_on=None

def upgrade():
    op.create_table('workbench_jobs',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('project_id',sa.Uuid(),sa.ForeignKey('projects.id'),nullable=False),
        sa.Column('name',sa.String(255),nullable=False),
        sa.Column('status',sa.String(32),nullable=False),
        sa.Column('config',sa.JSON(),nullable=False),sa.Column('result',sa.JSON()),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))

def downgrade():
    if op.get_bind().execute(sa.text('SELECT count(*) FROM workbench_jobs')).scalar_one():
        raise RuntimeError('refusing to discard workbench history')
    op.drop_table('workbench_jobs')
