import os, asyncio, logging, hashlib
from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import select, insert, delete
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .db import (
    init_db, async_session,
    Device, Heartbeat,
    DeviceToken, IssuedCert,
)

app = FastAPI(title="Edge-Cloud Control Plane (v0.4)")

CA_CERT_PATH = "/certs/ca.crt"
CA_KEY_PATH  = "/certs/ca.key"
# ────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ────────────────────────────────────────────────────────────────────────────
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

# admin API
class TokenIn(BaseModel):
    device_id: str
    token: str
class TokenOut(TokenIn):
    pass
# ────────────────────────────────────────────────────────────────────────────
# Start-up: ensure DB schema, start expiry scanner
# ────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def start_up() -> None:
    await init_db()
    asyncio.create_task(cert_expiry_scan())

async def cert_expiry_scan():
    """Log certs that will expire within 30 days; runs once per day."""
    while True:
        cutoff = datetime.utcnow() + timedelta(days=30)
        async with async_session() as sess:
            rows = (await sess.execute(
                select(IssuedCert).where(IssuedCert.not_after <= cutoff)
            )).scalars().all()
            for row in rows:
                logging.warning("CERT EXPIRING SOON %s device=%s expires=%s",
                                row.fingerprint[:16], row.device_id, row.not_after)
        await asyncio.sleep(24 * 3600)
# ────────────────────────────────────────────────────────────────────────────
# Heart-beat
# ────────────────────────────────────────────────────────────────────────────
@app.post("/heartbeat")
async def heartbeat(hb: HeartbeatIn):
    async with async_session() as sess:
        dev = await sess.get(Device, hb.device_id)
        if dev is None:
            dev = Device(id=hb.device_id, last_seen=hb.ts)
            sess.add(dev)
        else:
            dev.last_seen = hb.ts
        sess.add(Heartbeat(device_id=hb.device_id, ts=hb.ts))
        await sess.commit()
    return {"status": "ok"}
# ────────────────────────────────────────────────────────────────────────────
# Fleet overview
# ────────────────────────────────────────────────────────────────────────────
@app.get("/devices", response_model=List[DeviceOut])
async def list_devices():
    async with async_session() as sess:
        rows = (await sess.execute(
            select(Device).order_by(Device.last_seen.desc())
        )).scalars().all()
        return [DeviceOut(id=r.id, last_seen=r.last_seen) for r in rows]
# ────────────────────────────────────────────────────────────────────────────
# /register  – sign CSR after token check, store fingerprint
# ────────────────────────────────────────────────────────────────────────────
@app.post("/register", response_model=CertOut)
async def register(
    payload: CsrIn,
    x_register_token: str | None = Header(None, alias="X-Register-Token"),
):
    # 1 token check (DB)
    async with async_session() as sess:
        tok = await sess.get(DeviceToken, payload.device_id)
    if tok is None or tok.token != x_register_token:
        raise HTTPException(401, "invalid token")

    # 2 sign certificate
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    try:
        csr = x509.load_pem_x509_csr(payload.csr_pem.encode())
    except ValueError:
        raise HTTPException(400, "invalid CSR")
    if not csr.is_signature_valid:
        raise HTTPException(400, "CSR signature invalid")

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(payload.device_id)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem   = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # 3 store fingerprint
    fp = hashlib.sha256(cert_pem.encode()).hexdigest()
    async with async_session() as sess:
        sess.add(IssuedCert(
            fingerprint=fp,
            device_id=payload.device_id,
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
        ))
        await sess.commit()

    return CertOut(cert_pem=cert_pem, ca_pem=ca_pem)
# ────────────────────────────────────────────────────────────────────────────
# /tokens  – simple admin API (list / upsert / delete)
# ────────────────────────────────────────────────────────────────────────────
def admin_guard(hdr: str | None):
    if hdr != os.getenv("ADMIN_TOKEN"):
        raise HTTPException(401, "admin token required")

@app.get("/tokens", response_model=List[TokenOut])
async def list_tokens(x_admin_token: str | None = Header(None, alias="X-Admin-Token")):
    admin_guard(x_admin_token)
    async with async_session() as sess:
        rows = (await sess.execute(select(DeviceToken))).scalars().all()
        return rows

@app.post("/tokens", status_code=201)
async def upsert_token(
    tok: TokenIn,
    x_admin_token: str | None = Header(None, alias="X-Admin-Token")
):
    admin_guard(x_admin_token)
    async with async_session() as sess:
        await sess.merge(DeviceToken(device_id=tok.device_id, token=tok.token))
        await sess.commit()
    return {"status": "upserted"}

@app.delete("/tokens/{device_id}", status_code=204)
async def delete_token(
    device_id: str,
    x_admin_token: str | None = Header(None, alias="X-Admin-Token")
):
    admin_guard(x_admin_token)
    async with async_session() as sess:
        await sess.execute(delete(DeviceToken).where(DeviceToken.device_id == device_id))
        await sess.commit()