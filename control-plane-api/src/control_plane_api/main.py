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
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

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

heartbeat_requests = Counter('api_heartbeat_requests_total', 'Total number of heartbeat requests', ['device_id'])
workflow_requests  = Counter('api_workflow_requests_total',  'Total number of workflow CRUD calls', ['operation'])
log_requests       = Counter('api_workflow_log_requests_total','Total number of workflow log calls', ['operation'])
job_requests       = Counter('api_job_requests_total',      'Job claim / update calls', ['operation','device_id'])

# ── CORS ──────────────────────────────────────────────────────────────────
origins = os.getenv("CORS_ORIGINS","http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CA_CERT_PATH = "/certs/ca.crt"
CA_KEY_PATH  = "/certs/ca.key"
ADMIN_TOKEN  = os.getenv("ADMIN_TOKEN","")

# ── Dependency ─────────────────────────────────────────────────────────────
async def get_session() -> AsyncGenerator[AsyncSession,None]:
    async with async_session() as sess:
        yield sess

# ── Pydantic models ───────────────────────────────────────────────────────
class HeartbeatIn(BaseModel):
    device_id: str
    ts:        datetime

class DeviceOut(BaseModel):
    id:         str
    last_seen:  datetime

class CsrIn(BaseModel):
    device_id: str
    csr_pem:   str

class CertOut(BaseModel):
    cert_pem: str
    ca_pem:   str

class TokenIn(BaseModel):
    device_id: str
    token:     str

class TokenOut(TokenIn): pass

class WorkflowIn(BaseModel):
    name:       str
    definition: dict
    schedule:   Optional[str] = None
    recurrence: Optional[str] = None

class WorkflowOut(WorkflowIn):
    id:         int
    created_at: datetime
    updated_at: datetime

class LogIn(BaseModel):
    ts:      datetime
    success: bool
    output:  Optional[str] = None

class LogOut(LogIn):
    id: int

class JobOut(BaseModel):
    id:          int
    workflow_id: int
    state:       JobState
    payload:     dict|None = None

class JobUpdateIn(BaseModel):
    state:       JobState
    result:      dict|None = None
    error:       str|None  = None
    started_at:  datetime|None = None
    finished_at: datetime|None = None

class JobDetail(JobOut):
    result:      dict|None  = None
    error:       str|None   = None
    started_at:  datetime|None = None
    finished_at: datetime|None = None

class HeartbeatItem(BaseModel):
    device_id: str
    ts:        datetime

class BulkHeartbeatRequest(BaseModel):
    heartbeats: List[HeartbeatItem]

# ── APScheduler setup ─────────────────────────────────────────────────────
scheduler = AsyncIOScheduler()

async def enqueue_workflow_job(workflow_id: int):
    async with async_session() as sess:
        wf = await sess.get(Workflow, workflow_id)
        if not wf:
            return
        sess.add(Job(
            device_id=wf.device_id,
            workflow_id=workflow_id,
            state=JobState.QUEUED,
            payload={},
        ))
        await sess.commit()

def schedule_cron_for(wf: Workflow):
    job_id = f"wf-{wf.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if wf.schedule:
        trigger = CronTrigger.from_crontab(wf.schedule)
        scheduler.add_job(
            enqueue_workflow_job,
            trigger,
            args=[wf.id],
            id=job_id,
            name=f"workflow {wf.id} ({wf.name})"
        )

# ── Shared helpers ────────────────────────────────────────────────────────
async def _upsert_heartbeat(sess: AsyncSession, device_id: str, ts: datetime):
    await sess.execute(
        insert(Device)
        .values(id=device_id,last_seen=ts)
        .on_conflict_do_update(index_elements=[Device.id],set_={"last_seen":ts})
    )
    await sess.execute(
        insert(Heartbeat)
        .values(device_id=device_id,ts=ts)
    )

async def seed_token_only():
    async with async_session() as sess:
        exists = (await sess.execute(select(DeviceToken).limit(1))).first()
        if not exists:
            default = os.getenv("REG_TOKEN","my-super-secret-token")
            sess.add(DeviceToken(device_id="pi-01",token=default))
            await sess.commit()

async def cert_expiry_scan():
    while True:
        cutoff = datetime.utcnow() + timedelta(days=30)
        async with async_session() as sess:
            expiring = (await sess.execute(
                select(IssuedCert).where(IssuedCert.not_after<=cutoff)
            )).scalars().all()
            for row in expiring:
                logging.warning(
                    "CERT EXPIRING SOON: %s… device=%s expires=%s",
                    row.fingerprint[:16],row.device_id,row.not_after
                )
        await asyncio.sleep(24*3600)

# ── Single startup hook ──────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    # 1) DB init or seed
    if os.getenv("USE_CREATE_ALL") == "1":
        await init_db()
    else:
        await seed_token_only()

    # 2) schedule existing workflows
    async with async_session() as sess:
        wfs = (await sess.execute(
            select(Workflow).where(Workflow.schedule is not None)
        )).scalars().all()
        for wf in wfs:
            schedule_cron_for(wf)

    # 3) start scheduler
    scheduler.start()

    # 4) kick off cert‐expiry scanner
    asyncio.create_task(cert_expiry_scan())

# ── Heartbeat endpoints ───────────────────────────────────────────────────
@app.post("/heartbeat")
async def heartbeat(hb: HeartbeatIn, sess: AsyncSession = Depends(get_session)):
    heartbeat_requests.labels(device_id=hb.device_id).inc()
    await _upsert_heartbeat(sess, hb.device_id, hb.ts)
    await sess.commit()
    return {"status":"ok"}

@app.post("/heartbeat/bulk", status_code=204)
async def heartbeat_bulk(req: BulkHeartbeatRequest):
    async with async_session() as sess:
        async with sess.begin():
            for hb in req.heartbeats:
                heartbeat_requests.labels(device_id=hb.device_id).inc()
                await _upsert_heartbeat(sess, hb.device_id, hb.ts)

# ── Fleet overview ───────────────────────────────────────────────────────
@app.get("/devices", response_model=List[DeviceOut])
async def list_devices(sess: AsyncSession = Depends(get_session)):
    rows = (await sess.execute(
        select(Device).order_by(Device.last_seen.desc())
    )).scalars().all()
    return [DeviceOut(id=r.id,last_seen=r.last_seen) for r in rows]

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
