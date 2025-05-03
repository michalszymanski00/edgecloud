"""
Alembic migration environment for Edge-Cloud control plane
Keeps asyncpg for application code but downgrades to a sync URL
for Alembic’s own connection.
"""

from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine.url import make_url, URL

cfg = context.config

# ── Logging ---------------------------------------------------------------
if cfg.config_file_name is not None:
    fileConfig(cfg.config_file_name)

# ── 1) Guarantee DATABASE_URL (async) -------------------------------------
ini_url = cfg.get_main_option("sqlalchemy.url")  # value from alembic.ini
if "DATABASE_URL" not in os.environ and ini_url:
    if ini_url.startswith("postgresql://"):
        async_url = ini_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    else:
        async_url = ini_url
    os.environ["DATABASE_URL"] = async_url   # control_plane_api.db will read this

# ── 2) Force Alembic itself to use a *sync* URL ----------------------------
def _sync_url(u: str) -> str:
    url_obj: URL = make_url(u)
    if url_obj.drivername.endswith("+asyncpg"):
        url_obj = url_obj.set(drivername="postgresql")
    return url_obj.render_as_string(hide_password=False)

# Override whatever is in alembic.ini with our DATABASE_URL (syncified)
sync_url = _sync_url(os.environ["DATABASE_URL"])
cfg.set_main_option("sqlalchemy.url", sync_url)

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
