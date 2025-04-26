import os, asyncio, logging, hashlib, binascii
from datetime import datetime
from sqlalchemy.ext.asyncio import (
    AsyncAttrs, create_async_engine, async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, func, select, insert

# ── connection --------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)

# ── base model --------------------------------------------------------------
class Base(AsyncAttrs, DeclarativeBase):
    pass

# ── core tables -------------------------------------------------------------
class Device(Base):
    __tablename__ = "devices"
    id:        Mapped[str]      = mapped_column(String, primary_key=True)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True))

class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id:        Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str]      = mapped_column(String, index=True)
    ts:        Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# ── NEW: token & cert tables ------------------------------------------------
class DeviceToken(Base):
    __tablename__ = "device_tokens"
    device_id: Mapped[str] = mapped_column(String, primary_key=True)
    token:     Mapped[str] = mapped_column(String, unique=True)

class IssuedCert(Base):
    __tablename__ = "issued_certs"
    fingerprint: Mapped[str]      = mapped_column(String, primary_key=True)  # SHA-256 hex
    device_id:   Mapped[str]      = mapped_column(String)
    not_before:  Mapped[datetime] = mapped_column(DateTime)
    not_after:   Mapped[datetime] = mapped_column(DateTime)

# ── init --------------------------------------------------------------------
async def init_db(retries: int = 5, delay: float = 2.0):
    """Create tables; retry while Postgres is still booting."""
    for attempt in range(1, retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

                # ── seed one token if table is empty (simple PoC)
                res = await conn.execute(select(DeviceToken).limit(1))
                if res.first() is None:
                    token = os.getenv("REG_TOKEN") or "my-super-secret-token"
                    await conn.execute(
                        insert(DeviceToken).values(device_id="pi-01", token=token)
                    )

            logging.info("DB schema ready")
            return
        except Exception as exc:
            logging.warning("DB not ready (%s) – retry %s/%s", exc, attempt, retries)
            await asyncio.sleep(delay)
    raise RuntimeError("database unavailable")