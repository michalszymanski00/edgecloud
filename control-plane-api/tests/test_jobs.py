import os
import pytest_asyncio
import pytest
from httpx import AsyncClient, ASGITransport

# ── Pre‑setup env before importing app/db ───────────────────────
os.environ["USE_CREATE_ALL"] = "1"
os.environ["ADMIN_TOKEN"]    = "my-super-secret-token"
os.environ["DATABASE_URL"]   = "sqlite+aiosqlite:///:memory:"

from control_plane_api.main import app
from control_plane_api.db   import init_db

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_db():
    await init_db()
    yield

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

@pytest.mark.asyncio
async def test_job_lifecycle(client):
    # 1) create a workflow
    resp = await client.post(
        "/devices/pi-01/workflows",
        json={"name":"smoke","definition":{}},
        headers={"X-Register-Token":"my-super-secret-token"},
    )
    assert resp.status_code == 201
    wf_id = resp.json()["id"]

    # 2) insert a queued job directly
    from control_plane_api.db import async_session, Job, JobState
    from sqlalchemy import insert
    from datetime import datetime

    async with async_session() as sess:
        await sess.execute(
            insert(Job).values(
                device_id="pi-01",
                workflow_id=wf_id,
                state=JobState.QUEUED,
                payload={},
                created_at=datetime.utcnow(),
            )
        )
        await sess.commit()

    # 3) claim it
    resp = await client.get(
        "/devices/pi-01/jobs/next",
        headers={"X-Register-Token":"my-super-secret-token"},
    )
    assert resp.status_code == 200
    job = resp.json()
    assert job["state"] == "claimed"
    job_id = job["id"]

    # 4) PATCH it to succeeded (with explicit finished_at)
    fixed_finish = "2025-01-01T00:00:00Z"
    resp = await client.patch(
        f"/jobs/{job_id}",
        json={
            "state": "succeeded",
            "result": {"ok": True},
            "finished_at": fixed_finish,
        },
        headers={"X-Register-Token":"my-super-secret-token"},
    )
    assert resp.status_code == 204

    # 5) GET it back and validate all fields
    resp = await client.get(
        f"/jobs/{job_id}",
        headers={"X-Register-Token":"my-super-secret-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == job_id
    assert body["workflow_id"] == wf_id
    assert body["state"] == "succeeded"
    assert body["payload"] == {}
    assert body["result"] == {"ok": True}
    assert body["error"] is None
    assert body["started_at"] is None
    # allow missing Z suffix in ISO datetime
    assert body["finished_at"].rstrip("Z") == fixed_finish.rstrip("Z")
