import os
import asyncio
import logging
import hashlib
from datetime import datetime, timedelta
from typing import AsyncGenerator, List, Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from prometheus_client import Counter
from starlette_exporter import PrometheusMiddleware, handle_metrics

from .db import (
    init_db, async_session,
    Device, Heartbeat,
    DeviceToken, IssuedCert,
    Workflow, WorkflowLog,
    Job, JobState,
)

# ── FastAPI & metrics ────────────────────────────────────────────────────
app = FastAPI(title="Edge-Cloud Control Plane (v0.4+)")
app.add_middleware(PrometheusMiddleware, app_name="edge_cloud_api", prefix="http")
app.add_route("/metrics", handle_metrics)

heartbeat_requests = Counter(
    'api_heartbeat_requests_total',
    'Total number of heartbeat requests',
    ['device_id'],
)
workflow_requests = Counter(
    'api_workflow_requests_total',
    'Total number of workflow CRUD calls',
    ['operation'],
)
log_requests = Counter(
    'api_workflow_log_requests_total',
    'Total number of workflow log calls',
    ['operation'],
)
job_requests = Counter(
    'api_job_requests_total',
    'Job claim / update calls',
    ['operation', 'device_id'],
)

# ── CORS ──────────────────────────────────────────────────────────────────
origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CA_CERT_PATH = "/certs/ca.crt"
CA_KEY_PATH = "/certs/ca.key"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# ── Dependency: get a session ─────────────────────────────────────────────
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as sess:
        yield sess

# ── Pydantic models ───────────────────────────────────────────────────────
class HeartbeatIn(BaseModel):
    device_id: str
    ts: datetime

class DeviceOut(BaseModel):
    id: str
    last_seen: datetime

class CsrIn(BaseModel):
    device_id: str
    csr_pem: str

class CertOut(BaseModel):
    cert_pem: str
    ca_pem: str

class TokenIn(BaseModel):
    device_id: str
    token: str

class TokenOut(TokenIn):
    pass

class WorkflowIn(BaseModel):
    name: str
    definition: dict
    schedule: Optional[str] = None
    recurrence: Optional[str] = None

class WorkflowOut(WorkflowIn):
    id: int
    created_at: datetime
    updated_at: datetime

class LogIn(BaseModel):
    ts:       datetime
    success:  bool
    output:   Optional[str] = None

class LogOut(LogIn):
    id: int

class JobOut(BaseModel):
    id:          int
    workflow_id: int
    state:       JobState
    payload:     dict | None = None

class JobUpdateIn(BaseModel):
    state:       JobState
    result:      dict | None = None
    error:       str  | None = None
    started_at:  datetime | None = None
    finished_at: datetime | None = None

# ── Bulk‐heartbeat models & helper ────────────────────────────────────────
class HeartbeatItem(BaseModel):
    device_id: str
    ts: datetime

class BulkHeartbeatRequest(BaseModel):
    heartbeats: List[HeartbeatItem]

async def _upsert_heartbeat(sess: AsyncSession, device_id: str, ts: datetime):
    # upsert Device
    await sess.execute(
        insert(Device)
        .values(id=device_id, last_seen=ts)
        .on_conflict_do_update(
            index_elements=[Device.id],
            set_={"last_seen": ts},
        )
    )
    # insert Heartbeat row
    await sess.execute(
        insert(Heartbeat)
        .values(device_id=device_id, ts=ts)
    )

# ── Seed default token ────────────────────────────────────────────────────
async def seed_token_only():
    async with async_session() as sess:
        exists = (await sess.execute(select(DeviceToken).limit(1))).first()
        if not exists:
            default = os.getenv("REG_TOKEN", "my-super-secret-token")
            sess.add(DeviceToken(device_id="pi-01", token=default))
            await sess.commit()

# ── Startup tasks ────────────────────────────────────────────────────────
@app.on_event("startup")
async def start_up() -> None:
    if os.getenv("USE_CREATE_ALL", "") == "1":
        await init_db()
    else:
        await seed_token_only()
    asyncio.create_task(cert_expiry_scan())

async def cert_expiry_scan():
    while True:
        cutoff = datetime.utcnow() + timedelta(days=30)
        async with async_session() as sess:
            expiring = (
                await sess.execute(
                    select(IssuedCert).where(IssuedCert.not_after <= cutoff)
                )
            ).scalars().all()
            for row in expiring:
                logging.warning(
                    "CERT EXPIRING SOON: %s… device=%s expires=%s",
                    row.fingerprint[:16],
                    row.device_id,
                    row.not_after,
                )
        await asyncio.sleep(24 * 3600)

# ── Heartbeat single ─────────────────────────────────────────────────────
@app.post("/heartbeat")
async def heartbeat(
    hb: HeartbeatIn,
    sess: AsyncSession = Depends(get_session),
):
    heartbeat_requests.labels(device_id=hb.device_id).inc()
    await _upsert_heartbeat(sess, hb.device_id, hb.ts)
    await sess.commit()
    return {"status": "ok"}

# ── Heartbeat bulk ───────────────────────────────────────────────────────
@app.post("/heartbeat/bulk", status_code=204)
async def heartbeat_bulk(req: BulkHeartbeatRequest):
    """
    Accept a list of {device_id, ts} items and upsert each heartbeat
    in a single transaction.
    """
    async with async_session() as sess:
        async with sess.begin():
            for hb in req.heartbeats:
                heartbeat_requests.labels(device_id=hb.device_id).inc()
                await _upsert_heartbeat(sess, hb.device_id, hb.ts)
    return

# ── Fleet overview ───────────────────────────────────────────────────────
@app.get("/devices", response_model=List[DeviceOut])
async def list_devices(
    sess: AsyncSession = Depends(get_session),
):
    rows = (
        await sess.execute(
            select(Device).order_by(Device.last_seen.desc())
        )
    ).scalars().all()
    return [DeviceOut(id=r.id, last_seen=r.last_seen) for r in rows]

# ── Device enrollment ─────────────────────────────────────────────────────
@app.post("/register", response_model=CertOut)
async def register(
    payload: CsrIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    tok = await sess.get(DeviceToken, payload.device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")

    # load CA
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # parse CSR
    try:
        csr = x509.load_pem_x509_csr(payload.csr_pem.encode())
    except ValueError:
        raise HTTPException(400, "invalid CSR")
    if not csr.is_signature_valid:
        raise HTTPException(400, "CSR signature invalid")

    # sign certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(payload.device_id)]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # store issued cert record
    fp = hashlib.sha256(cert_pem.encode()).hexdigest()
    sess.add(
        IssuedCert(
            fingerprint=fp,
            device_id=payload.device_id,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
        )
    )
    await sess.commit()

    return CertOut(cert_pem=cert_pem, ca_pem=ca_pem)

# ── Admin‐only token CRUD ──────────────────────────────────────────────────
def require_admin(x_admin: str):
    if x_admin != ADMIN_TOKEN:
        raise HTTPException(401, "admin token required")

@app.get("/tokens", response_model=List[TokenOut])
async def list_tokens(
    x_admin_token: str = Header(..., alias="X-Admin-Token"),
    sess: AsyncSession = Depends(get_session),
):
    require_admin(x_admin_token)
    return (await sess.execute(select(DeviceToken))).scalars().all()

@app.post("/tokens", status_code=201)
async def upsert_token(
    tok: TokenIn,
    x_admin_token: str = Header(..., alias="X-Admin-Token"),
    sess: AsyncSession = Depends(get_session),
):
    require_admin(x_admin_token)
    stmt = (
        insert(DeviceToken)
        .values(device_id=tok.device_id, token=tok.token)
        .on_conflict_do_update(
            index_elements=[DeviceToken.device_id],
            set_={"token": tok.token},
        )
    )
    await sess.execute(stmt)
    await sess.commit()
    return {"status": "upserted"}

@app.delete("/tokens/{device_id}", status_code=204)
async def delete_token(
    device_id: str,
    x_admin_token: str = Header(..., alias="X-Admin-Token"),
    sess: AsyncSession = Depends(get_session),
):
    require_admin(x_admin_token)
    await sess.execute(
        delete(DeviceToken).where(DeviceToken.device_id == device_id)
    )
    await sess.commit()

# ── Workflow CRUD ────────────────────────────────────────────────────────
@app.get(
    "/devices/{device_id}/workflows",
    response_model=List[WorkflowOut],
)
async def list_workflows(
    device_id: str,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    rows = (
        await sess.execute(
            select(Workflow).where(Workflow.device_id == device_id)
        )
    ).scalars().all()
    return rows

@app.post(
    "/devices/{device_id}/workflows",
    response_model=WorkflowOut,
    status_code=201,
)
async def create_workflow(
    device_id: str,
    wf: WorkflowIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    new = Workflow(
        device_id=device_id,
        name=wf.name,
        definition=wf.definition,
        schedule=wf.schedule,
        recurrence=wf.recurrence,
    )
    sess.add(new)
    await sess.commit()
    await sess.refresh(new)
    return new

@app.put(
    "/devices/{device_id}/workflows/{workflow_id}",
    response_model=WorkflowOut,
)
async def update_workflow(
    device_id: str,
    workflow_id: int,
    wf: WorkflowIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    ex = await sess.get(Workflow, workflow_id)
    if ex is None or ex.device_id != device_id:
        raise HTTPException(404, "not found")
    ex.name = wf.name
    ex.definition = wf.definition
    ex.schedule = wf.schedule
    ex.recurrence = wf.recurrence
    await sess.commit()
    await sess.refresh(ex)
    return ex

@app.delete(
    "/devices/{device_id}/workflows/{workflow_id}",
    status_code=204,
)
async def delete_workflow(
    device_id: str,
    workflow_id: int,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    await sess.execute(
        delete(Workflow)
        .where(Workflow.id == workflow_id, Workflow.device_id == device_id)
    )
    await sess.commit()

# ── Workflow Logs ────────────────────────────────────────────────────────
@app.post(
    "/devices/{device_id}/workflows/{workflow_id}/logs",
    response_model=LogOut,
    status_code=201,
)
async def create_log(
    device_id: str,
    workflow_id: int,
    log: LogIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    log_requests.labels(operation='create').inc()
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    entry = WorkflowLog(
        device_id=device_id,
        workflow_id=workflow_id,
        ts=log.ts,
        success=log.success,
        output=log.output,
    )
    sess.add(entry)
    await sess.commit()
    await sess.refresh(entry)
    return LogOut(
        id=entry.id,
        ts=entry.ts,
        success=entry.success,
        output=entry.output,
    )

@app.get(
    "/devices/{device_id}/workflows/{workflow_id}/logs",
    response_model=List[LogOut],
)
async def list_logs(
    device_id: str,
    workflow_id: int,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    log_requests.labels(operation='list').inc()
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")
    rows = (
        await sess.execute(
            select(WorkflowLog)
            .where(
                WorkflowLog.device_id == device_id,
                WorkflowLog.workflow_id == workflow_id,
            )
            .order_by(WorkflowLog.ts.desc())
        )
    ).scalars().all()
    return [
        LogOut(
            id=r.id,
            ts=r.ts,
            success=r.success,
            output=r.output,
        ) for r in rows
    ]

# ── Job claim & update ───────────────────────────────────────────────────
@app.get("/devices/{device_id}/jobs/next", response_model=JobOut | None)
async def claim_next_job(
    device_id: str,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    job_requests.labels(operation="claim", device_id=device_id).inc()
    tok = await sess.get(DeviceToken, device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")

    async with sess.begin():
        stmt = (
            select(Job)
            .where(Job.device_id == device_id, Job.state == JobState.QUEUED)
            .order_by(Job.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        job = (await sess.scalars(stmt)).first()
        if not job:
            return None
        job.state = JobState.CLAIMED
        job.claimed_at = datetime.utcnow()
    await sess.commit()
    return JobOut(
        id=job.id,
        workflow_id=job.workflow_id,
        state=job.state,
        payload=job.payload,
    )

@app.patch("/jobs/{job_id}", status_code=204)
async def update_job(
    job_id: int,
    patch: JobUpdateIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
    sess: AsyncSession = Depends(get_session),
):
    job = await sess.get(Job, job_id)
    if not job:
        raise HTTPException(404, "job not found")
    job_requests.labels(operation="update", device_id=job.device_id).inc()
    tok = await sess.get(DeviceToken, job.device_id)
    if not tok or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")

    job.state = patch.state
    job.result = patch.result
    job.error = patch.error
    job.started_at = patch.started_at or job.started_at
    job.finished_at = (
        patch.finished_at
        or (
            datetime.utcnow()
            if patch.state in (
                JobState.SUCCEEDED,
                JobState.FAILED,
                JobState.CANCELED,
            )
            else None
        )
    )
    await sess.commit()
