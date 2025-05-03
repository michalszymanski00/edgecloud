# ── src/control_plane_api/db.py ──────────────────────────────────────────
import os
import asyncio
import logging
import enum
from datetime import datetime

from sqlalchemy import (
    Enum as PgEnum, String, Integer, JSON, ForeignKey, Index,
    DateTime as SA_DateTime, func, select, insert
)
from sqlalchemy.ext.asyncio import (
    AsyncAttrs, create_async_engine, async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# ───────────────────────── connection ────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
engine        = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)

# ───────────────────────── base class ────────────────────────────────────
class Base(AsyncAttrs, DeclarativeBase):
    pass

# ───────────────────────── core tables ───────────────────────────────────
class Device(Base):
    __tablename__ = "devices"

    id:         Mapped[str]      = mapped_column(String, primary_key=True)
    last_seen:  Mapped[datetime] = mapped_column(SA_DateTime(timezone=True))

    workflows = relationship("Workflow", back_populates="device",
                             cascade="all, delete-orphan")
    jobs      = relationship("Job",      back_populates="device",
                             cascade="all, delete-orphan")


class Heartbeat(Base):
    __tablename__ = "heartbeats"

    id:        Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str]      = mapped_column(String, index=True)
    ts:        Mapped[datetime] = mapped_column(SA_DateTime(timezone=True),
                                               server_default=func.now())


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

    __table_args__ = (Index("ix_issued_certs_not_after", "not_after"),)


# ───────────────────────── workflows ─────────────────────────────────────
class Workflow(Base):
    __tablename__ = "workflows"

    id:         Mapped[int]   = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id:  Mapped[str]   = mapped_column(String, ForeignKey("devices.id"), index=True)
    name:       Mapped[str]   = mapped_column(String, nullable=False)
    definition: Mapped[dict]  = mapped_column(JSON,    nullable=False)

    # schedule field now stored as cron string
    schedule:   Mapped[str | None] = mapped_column(String, nullable=True)
    recurrence: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(SA_DateTime(timezone=True),
                                                 server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(SA_DateTime(timezone=True),
                                                 server_default=func.now(),
                                                 onupdate=func.now())

    device = relationship("Device", back_populates="workflows")
    jobs   = relationship("Job",    back_populates="workflow",
                          cascade="all, delete-orphan")


class WorkflowLog(Base):
    __tablename__ = "workflow_logs"

    id:          Mapped[int]      = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id:   Mapped[str]      = mapped_column(String, index=True)
    workflow_id: Mapped[int]      = mapped_column(Integer, index=True)
    ts:          Mapped[datetime] = mapped_column(SA_DateTime(timezone=True),
                                                 server_default=func.now())
    success:     Mapped[bool]
    output:      Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (Index("ix_workflow_logs_device_wf",
                            "device_id", "workflow_id"),)


# ───────── jobs ────────────────────────────────────────────────────────
class JobState(enum.Enum):
    QUEUED    = "queued"
    CLAIMED   = "claimed"
    RUNNING   = "running"
    SUCCEEDED = "succeeded"
    FAILED    = "failed"
    CANCELED  = "canceled"


class Job(Base):
    __tablename__ = "jobs"

    id:          Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id:   Mapped[str]  = mapped_column(String, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    workflow_id: Mapped[int]  = mapped_column(Integer, ForeignKey("workflows.id", ondelete="CASCADE"), index=True)

    state: Mapped[JobState] = mapped_column(
        PgEnum(
            JobState,
            name="jobstate",
            create_constraint=False,
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=JobState.QUEUED,
        index=True,
    )

    payload:     Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result:      Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error:       Mapped[str  | None] = mapped_column(String, nullable=True)

    created_at:  Mapped[datetime]       = mapped_column(SA_DateTime(timezone=True), server_default=func.now())
    claimed_at:  Mapped[datetime | None] = mapped_column(SA_DateTime(timezone=True))
    started_at:  Mapped[datetime | None] = mapped_column(SA_DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(SA_DateTime(timezone=True))

    device   = relationship("Device",   back_populates="jobs")
    workflow = relationship("Workflow", back_populates="jobs")

# ──────────────────────── init / seed helper ─────────────────────────────
async def init_db(retries: int = 5, delay: float = 2.0) -> None:
    """
    Create tables (only in dev) and insert one default registration
    token if none exists.
    """
    for attempt in range(1, retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

                if (await conn.execute(select(DeviceToken).limit(1))).first() is None:
                    default = os.getenv("REG_TOKEN", "my-super-secret-token")
                    await conn.execute(
                        insert(DeviceToken).values(device_id="pi-01", token=default)
                    )
            logging.info("DB schema ready (create_all) and default token seeded")
            return
        except Exception as exc:
            logging.warning("DB not ready (%s) – retry %s/%s", exc, attempt, retries)
            await asyncio.sleep(delay)
    raise RuntimeError("database unavailable")
