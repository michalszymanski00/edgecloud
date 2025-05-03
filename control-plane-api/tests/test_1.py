import os
import pytest_asyncio
import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from control_plane_api.main import app
from control_plane_api.db import init_db

# Ensure these environment variables before app startup
os.environ["USE_CREATE_ALL"] = "1"
os.environ["ADMIN_TOKEN"] = "admintok"
# Database URL for in-memory SQLite (tests only)
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_db():
    # Initialize schema
    await init_db()
    yield

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

@pytest.mark.asyncio
async def test_heartbeat_and_devices(client):
    # Single heartbeat
    ts = "2025-01-01T00:00:00Z"
    resp = await client.post("/heartbeat", json={"device_id": "dev1", "ts": ts})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # Verify device shows up
    resp = await client.get("/devices")
    assert resp.status_code == 200
    devices = resp.json()
    assert any(d["id"] == "dev1" for d in devices)

@pytest.mark.asyncio
async def test_bulk_heartbeat(client):
    # Bulk heartbeat
    ts1 = "2025-01-01T01:00:00Z"
    ts2 = "2025-01-01T02:00:00Z"
    payload = {"heartbeats": [
        {"device_id": "dev2", "ts": ts1},
        {"device_id": "dev3", "ts": ts2}
    ]}
    resp = await client.post("/heartbeat/bulk", json=payload)
    assert resp.status_code == 204

    # Verify devices
    resp = await client.get("/devices")
    ids = {d["id"] for d in resp.json()}
    assert {"dev2", "dev3"}.issubset(ids)

@pytest.mark.asyncio
async def test_token_crud(client):
    # Unauthorized fetch
    resp = await client.get("/tokens", headers={"X-Admin-Token": "wrong"})
    assert resp.status_code == 401

    # Authorized fetch (empty)
    resp = await client.get("/tokens", headers={"X-Admin-Token": "admintok"})
    assert resp.status_code == 200
    assert resp.json() == []

    # Upsert token
    tok = {"device_id": "d1", "token": "tok1"}
    resp = await client.post("/tokens", json=tok, headers={"X-Admin-Token": "admintok"})
    assert resp.status_code == 201

    # Fetch back
    resp = await client.get("/tokens", headers={"X-Admin-Token": "admintok"})
    assert resp.status_code == 200
    assert tok in resp.json()

    # Delete token
    resp = await client.delete("/tokens/d1", headers={"X-Admin-Token": "admintok"})
    assert resp.status_code == 204

@pytest.mark.asyncio
async def test_workflow_crud(client):
    # Seed a registration token via admin API
    tok = {"device_id": "d2", "token": "tok2"}
    resp = await client.post("/tokens", json=tok, headers={"X-Admin-Token": "admintok"})
    assert resp.status_code == 201

    # Create workflow
    wf_data = {"name": "w1", "definition": {"foo": "bar"}, "schedule": None, "recurrence": None}
    resp = await client.post(
        "/devices/d2/workflows", json=wf_data,
        headers={"X-Register-Token": "tok2"}
    )
    assert resp.status_code == 201
    wf = resp.json()
    wf_id = wf["id"]

    # List workflows
    resp = await client.get(
        "/devices/d2/workflows", headers={"X-Register-Token": "tok2"}
    )
    assert resp.status_code == 200
    assert any(w["id"] == wf_id for w in resp.json())

    # Update workflow
    update_data = {"name": "w1u", "definition": {"foo": "baz"}, "schedule": None, "recurrence": None}
    resp = await client.put(
        f"/devices/d2/workflows/{wf_id}", json=update_data,
        headers={"X-Register-Token": "tok2"}
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "w1u"

    # Delete workflow
    resp = await client.delete(
        f"/devices/d2/workflows/{wf_id}",
        headers={"X-Register-Token": "tok2"}
    )
    assert resp.status_code == 204

    # Verify deletion
    resp = await client.get(
        "/devices/d2/workflows", headers={"X-Register-Token": "tok2"}
    )
    assert resp.status_code == 200
    assert all(w.get("id") != wf_id for w in resp.json())
