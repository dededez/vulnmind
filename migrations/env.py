import os
from alembic import context
from sqlalchemy import engine_from_config, pool
from vulnmind.persistence.base import Base
import vulnmind.persistence.models  # noqa: F401 -- register mappings for Alembic

config = context.config
url = os.environ.get("VULNMIND_DATABASE_URL")
if not url:
    raise RuntimeError("VULNMIND_DATABASE_URL must be set")
# Alembic config interpolation treats percent specially.
config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))

def run_migrations_offline():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
