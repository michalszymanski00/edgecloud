import os
import asyncio
import logging
from datetime import datetime

from sqlalchemy.ext.asyncio import (
    AsyncAttrs, create_async_engine, async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import (
    String, DateTime as SA_DateTime, func,
    select, insert,
    JSON, Integer, ForeignKey, Index
)

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
    last_seen: Mapped[datetime] = mapped_column(SA_DateTime(timezone=True))

    # relationship to workflows
    workflows = relationship(
        "Workflow",
        back_populates="device",
        cascade="all, delete-orphan"
    )

class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id:        Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str]      = mapped_column(String, index=True)
    ts:        Mapped[datetime] = mapped_column(SA_DateTime(timezone=True), server_default=func.now())

# ── token & cert tables -----------------------------------------------------
class DeviceToken(Base):
    __tablename__ = "device_tokens"
    device_id: Mapped[str] = mapped_column(String, primary_key=True)
    token:     Mapped[str] = mapped_column(String, unique=True)

class IssuedCert(Base):
    __tablename__ = "issued_certs"
    fingerprint: Mapped[str]      = mapped_column(String, primary_key=True)
    device_id:   Mapped[str]      = mapped_column(String, index=True)
    not_before:  Mapped[datetime] = mapped_column(SA_DateTime(timezone=True))
    not_after:   Mapped[datetime] = mapped_column(SA_DateTime(timezone=True))

    __table_args__ = (
        Index('ix_issued_certs_not_after', 'not_after'),
    )

# ── workflows table ---------------------------------------------------------

class Workflow(Base):
    __tablename__ = "workflows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String, ForeignKey("devices.id"), index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    definition: Mapped[dict] = mapped_column(JSON, nullable=False)

    schedule:   Mapped[dict] = mapped_column(JSON, nullable=True)
    recurrence: Mapped[str]  = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        SA_DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        SA_DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    device = relationship("Device", back_populates="workflows")

class WorkflowLog(Base):
    __tablename__ = "workflow_logs"
    id:         Mapped[int]      = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id:  Mapped[str]      = mapped_column(String, index=True)
    workflow_id:Mapped[int]      = mapped_column(Integer, index=True)
    ts:         Mapped[datetime] = mapped_column(
        SA_DateTime(timezone=True),
        server_default=func.now(),
    )
    success:    Mapped[bool]     = mapped_column(nullable=False)
    output:     Mapped[str]      = mapped_column(String, nullable=True)

    __table_args__ = (
        Index("ix_workflow_logs_device_wf", "device_id", "workflow_id"),
    )
# ── initialize / seed -------------------------------------------------------
async def init_db(retries: int = 5, delay: float = 2.0):
    """Create tables; retry while Postgres is still booting and seed default token."""
    for attempt in range(1, retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

                # seed one token if table is empty (PoC)
                res = await conn.execute(select(DeviceToken).limit(1))
                if res.first() is None:
                    default = os.getenv("REG_TOKEN") or "my-super-secret-token"
                    await conn.execute(
                        insert(DeviceToken).values(device_id="pi-01", token=default)
                    )

            logging.info("DB schema ready and default token seeded")
            return
        except Exception as exc:
            logging.warning(
                "DB not ready (%s) – retry %s/%s", exc, attempt, retries
            )
            await asyncio.sleep(delay)
    raise RuntimeError("database unavailable")