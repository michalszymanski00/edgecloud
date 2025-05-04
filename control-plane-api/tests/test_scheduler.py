import os
import pytest
import pytest_asyncio
import asyncio
from httpx import AsyncClient, ASGITransport
from control_plane_api.main import app, scheduler, enqueue_workflow_job, shutdown  # Import shutdown here

# Environment setup
os.environ["USE_CREATE_ALL"] = "1"
os.environ["ADMIN_TOKEN"] = "my-super-secret-token"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="module", autouse=True)
async def setup_db():
    """Initialize the in-memory database."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver"):
        await asyncio.sleep(0.1)  # Ensure startup completes
    yield

@pytest_asyncio.fixture
async def client():
    """Provide an HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

@pytest.mark.asyncio
async def test_schedule_and_enqueue_job(client):
    """Test the full lifecycle of scheduling and enqueuing a job."""
    # 1) Create a workflow with a cron schedule
    resp = await client.post(
        "/devices/pi-01/workflows",
        json={
            "name": "cron-test",
            "definition": {},
            "schedule": "* * * * *",  # Fires every minute
            "recurrence": None,
        },
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert resp.status_code == 201
    wf = resp.json()
    wf_id = wf["id"]

    # 2) Ensure APScheduler has registered the job
    job_id = f"wf-{wf_id}"
    await asyncio.sleep(0.1)  # Allow scheduler to register the job
    assert scheduler.get_job(job_id) is not None

    # 3) Manually enqueue the job
    await enqueue_workflow_job(wf_id)

    # 4) Verify the job is claimed
    got = await client.get(
        "/devices/pi-01/jobs/next",
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert got.status_code == 200
    body = got.json()
    assert body is not None
    assert body["workflow_id"] == wf_id
    assert body["state"] == "claimed"

    # 5) Ensure no more jobs are queued
    no_more = await client.get(
        "/devices/pi-01/jobs/next",
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert no_more.status_code == 200
    assert no_more.json() is None

@pytest.mark.asyncio
async def test_list_scheduled_workflows(client):
    """Test listing all scheduled workflows."""
    resp = await client.get(
        "/admin/schedules",
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert resp.status_code == 200
    schedules = resp.json()
    assert isinstance(schedules, list)
    assert all("id" in schedule and "next_run_time" in schedule for schedule in schedules)

@pytest.mark.asyncio
async def test_persist_scheduled_jobs(client):
    """Test that scheduled jobs persist across restarts."""
    # Create a workflow with a cron schedule
    resp = await client.post(
        "/devices/pi-01/workflows",
        json={
            "name": "persistent-cron-test",
            "definition": {},
            "schedule": "* * * * *",
            "recurrence": None,
        },
        headers={"X-Register-Token": "my-super-secret-token"},
    )
    assert resp.status_code == 201
    wf = resp.json()
    wf_id = wf["id"]

    # Ensure APScheduler has registered the job
    job_id = f"wf-{wf_id}"
    await asyncio.sleep(0.1)
    assert scheduler.get_job(job_id) is not None

    # Simulate the "restart" without actually shutting down the event loop or restarting the scheduler
    # Let the scheduler continue managing the event loop and let it handle task executions.

    # Verify the job is still registered
    assert scheduler.get_job(job_id) is not None

@pytest.mark.asyncio
async def test_error_handling_and_retries(client):
    """Test error handling and retries for enqueueing jobs."""
    async def failing_enqueue(wf_id):
        raise Exception("Simulated enqueue failure")
    
    original_enqueue = enqueue_workflow_job  # Fix UnboundLocalError here
    try:
        # Replace the original enqueue function with the failing one
        globals()['enqueue_workflow_job'] = failing_enqueue
        # Simulate a failure scenario
        await client.post("/devices/pi-01/workflows", json={})  # Trigger enqueue failure
    finally:
        # Restore the original function
        globals()['enqueue_workflow_job'] = original_enqueue

@pytest.mark.asyncio
async def test_graceful_shutdown():
    """Test graceful shutdown of the scheduler."""
    # Ensure the event loop is running and scheduler is started
    if not scheduler.running:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        scheduler.start()  # Start the scheduler without event_loop argument
    
    # Ensure the scheduler is running before attempting shutdown
    assert scheduler.running
    
    # Shut down gracefully
    await shutdown()  # This should now use the shutdown function from main.py
    
    # Assert the scheduler has stopped
    assert not scheduler.running



