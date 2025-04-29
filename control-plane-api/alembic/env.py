from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import url as sa_url

from alembic import context

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ─── Metadata for 'autogenerate' support ─────────────────────────────────
from control_plane_api.db import Base  # adjust import if needed

target_metadata = Base.metadata

# ─── Patch async URL for Alembic (strip async driver) ─────────────────────
def _patch_async_url():
    raw_url = config.get_main_option("sqlalchemy.url")
    if raw_url and raw_url.startswith("postgresql+asyncpg://"):
        u = sa_url.make_url(raw_url)
        sync_url = u.set(drivername="postgresql")
        config.set_main_option("sqlalchemy.url", str(sync_url))

# apply URL patch before engine creation
target_metadata = Base.metadata
_patch_async_url()


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()