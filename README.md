# Edge-Cloud Control Plane & Agent

**Date:** 2025-04-26–27  
**Participants:** You (Cloud DevOps Engineer), ChatGPT

---

## Overview

Today we designed and built an end-to-end **Edge-Cloud control plane** alongside a lightweight **edge agent**, then scaffolded a **React/Next.js dashboard**. Key components:

1. **Control-Plane API** (FastAPI + PostgreSQL)  
2. **Edge Agent** (Go, mTLS, auto-enrollment, self-update)  
3. **Docker Compose** orchestration  
4. **TLS & mTLS** setup (CA, server & client certs)  
5. **Authentication**: enrollment tokens, admin token  
6. **Cert Management**: issuance, fingerprint storage, expiry scanner  
7. **React Dashboard** (Next.js, Tailwind, CORS)

---

## 1. Control-Plane API

- **Tech Stack:** Python 3.12-slim, FastAPI, SQLAlchemy (async), asyncpg, uvicorn  
- **Folder:** `control-plane-api/`  
- **Key Endpoints:**
  - `POST /heartbeat` — upsert device & store heartbeat  
  - `GET /devices` — list devices (fleet overview)  
  - `POST /register` — sign CSR, return device cert + CA  
  - `GET/POST/DELETE /tokens` — admin token management  

### Highlights

- **Database Schema** in `db.py`:
  - `Device`, `Heartbeat`, `IssuedCert`, `DeviceToken`
  - `init_db()` with retry loop  
- **CORS** middleware configured via `CORS_ORIGINS` env  
- **Cert issuance** using `cryptography.x509`  
- **Fingerprint** stored in DB & daily expiry scan task  
- **Admin API** protected by `ADMIN_TOKEN`

---

## 2. Edge Agent

- **Tech Stack:** Go, `net/http`, `crypto/tls`, `x509`, GitHub self-update  
- **Features:**
  1. **Auto-enrollment**:
     - Generates RSA key + CSR
     - `POST /register`, saves `client.crt` & `ca.crt`
     - Uses `X-Register-Token` header for auth  
  2. **Heartbeat**:
     - Every 30 s sends `{device_id, ts}` to `/heartbeat` over mTLS  
  3. **Self-update**:
     - Periodically (env-driven `UPDATE_INTERVAL`) polls GitHub latest release
     - Downloads binary + SHA256 checksum
     - Verifies, atomically renames, re-executes  
- **Deployment**:
  - Installed under `/usr/local/bin`
  - Managed by systemd `edge-agent.service`

---

## 3. Docker Compose

- **Services:**
  - **db** — `postgres:17` with healthcheck  
  - **api** — built from `control-plane-api/`, mounted certs, TLS & mTLS listener  
- **Ports:**
  - `8443` — mTLS endpoint (heartbeat, requires client cert)  
  - `8444` — enrollment & dashboard API (no client cert)  
- **Volumes:** persisted `pgdata` for Postgres

---

## 4. TLS & mTLS Setup

- **CA & Certs** under `certs/` and `api-certs/`  
- Generated:
  - `ca.key` / `ca.crt` (root CA)  
  - `api.key` / `api.csr` / `api.crt` (server cert with IP SAN)  
  - Per-device certificates signed at enrollment  
- **Agent** trusts CA (`--ssl-ca-certs`), provides client cert for `/heartbeat`

---

## 5. React Dashboard

- **Folder:** `dashboard/`  
- **Stack:** Next.js (App Router), TypeScript, Tailwind CSS, Axios  
- **CORS:** pointed to `https://api.local:8444`, added `CORSMiddleware`  
- **Features:**
  1. Displays fleet table from `GET /devices`  
  2. Table shows `device_id` and `last_seen`  
- **Next Steps:** add expiry warnings, charts, token management UI

---

## How to Run Everything

```bash
# 1. Start control plane & db
docker compose up -d

# 2. Build & install agent, then on Pi:
scp edge-agent admin@pi:/usr/local/bin/edge-agent

# 3. Start systemd agent:
sudo systemctl enable --now edge-agent

# 4. Start dashboard:
cd dashboard
npm run dev
