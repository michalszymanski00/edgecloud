"""
Alembic migration environment for Edge-Cloud control plane
Keeps asyncpg for application code but downgrades to a sync URL
for Alembic’s own connection.
"""

from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import url as sa_url

cfg = context.config

# ── Logging ---------------------------------------------------------------
if cfg.config_file_name is not None:
    fileConfig(cfg.config_file_name)

# ── 1) Guarantee DATABASE_URL (async) -------------------------------------
ini_url = cfg.get_main_option("sqlalchemy.url")  # value from alembic.ini
if "DATABASE_URL" not in os.environ and ini_url:
    # If the ini URL is already async, great; otherwise upgrade it.
    if ini_url.startswith("postgresql://"):
        async_url = ini_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    else:
        async_url = ini_url
    os.environ["DATABASE_URL"] = async_url   # db.py will read this

# ── 2) Patch *Alembic’s* URL back to sync ---------------------------------
def _patch_async_url() -> None:
    raw = cfg.get_main_option("sqlalchemy.url")
    if raw and raw.startswith("postgresql+asyncpg://"):
        parsed = sa_url.make_url(raw).set(drivername="postgresql")
        cfg.set_main_option("sqlalchemy.url", str(parsed))

_patch_async_url()

# ── 3) Import metadata after env-var is set -------------------------------
from control_plane_api.db import Base  # noqa: E402

target_metadata = Base.metadata

# ── Runner helpers --------------------------------------------------------
def run_migrations_offline() -> None:
    context.configure(
        url=cfg.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        cfg.get_section(cfg.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()