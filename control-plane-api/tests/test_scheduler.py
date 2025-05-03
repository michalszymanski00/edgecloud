import os
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport

from control_plane_api.main import (
    app,
    scheduler,
    enqueue_workflow_job,
)
from control_plane_api.db import async_session, Workflow, Job

# make sure your env is set for in‑memory DB, etc.
os.environ["USE_CREATE_ALL"] = "1"
os.environ["ADMIN_TOKEN"]    = "my-super-secret-token"
os.environ["DATABASE_URL"]   = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="module", autouse=True)
async def setup_db():
    # kicks off init_db() via startup hook
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver"):
        # wait a tick so startup() runs
        await asyncio.sleep(0.1)
    yield

@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

@pytest.mark.asyncio
async def test_schedule_and_enqueue_job(client):
    # 1) create a workflow *with* a cron schedule (every minute)
    resp = await client.post(
        "/devices/pi-01/workflows",
        json={
            "name": "cron-test",
            "definition": {},
            "schedule": "* * * * *",  # fires every minute
            "recurrence": None,
        },
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert resp.status_code == 201
    wf = resp.json()
    wf_id = wf["id"]

    # 2) ensure APScheduler has registered the job
    job_id = f"wf-{wf_id}"
    # give the scheduler a moment to pick up your new job:
    await asyncio.sleep(0.1)
    assert scheduler.get_job(job_id) is not None

    # 3) manually *enqueue* it (simulate a cron trigger)
    await enqueue_workflow_job(wf_id)

    # 4) now talk to /devices/pi-01/jobs/next
    got = await client.get(
        "/devices/pi-01/jobs/next",
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert got.status_code == 200
    body = got.json()
    assert body is not None
    assert body["workflow_id"] == wf_id
    assert body["state"] == "claimed"

    # after claiming, there should be no more queued jobs
    no_more = await client.get(
        "/devices/pi-01/jobs/next",
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert no_more.status_code == 200
    assert no_more.json() is None
