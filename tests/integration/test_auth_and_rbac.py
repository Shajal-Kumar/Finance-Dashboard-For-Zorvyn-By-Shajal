"""
tests/integration/test_auth_and_rbac.py
────────────────────────────────────────
Integration tests covering auth, RBAC, CSRF, validation, and soft-delete.
"""

from __future__ import annotations
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def app():
    import os
    os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    os.environ.setdefault("APP_ENVIRONMENT", "development")
    os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL",    "admin@test.com")
    os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "AdminPass123!")

    from main import create_app
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _login(client, email, password):
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


async def _auth_headers(client, email, password):
    resp = await _login(client, email, password)
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.mark.anyio
async def test_login_success(client):
    resp = await _login(client, "admin@test.com", "AdminPass123!")
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.anyio
async def test_login_wrong_password_returns_401(client):
    resp = await _login(client, "admin@test.com", "WrongPassword!")
    assert resp.status_code == 401
    assert "Incorrect email or password" in resp.json()["message"]


@pytest.mark.anyio
async def test_protected_endpoint_without_token_returns_401(client):
    resp = await client.get("/api/v1/records")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_admin_can_create_record(client):
    headers = await _auth_headers(client, "admin@test.com", "AdminPass123!")
    get_resp   = await client.get("/api/v1/records", headers=headers)
    csrf_token = get_resp.cookies.get("csrf_token", "test-csrf")

    resp = await client.post(
        "/api/v1/records",
        json={"amount": 1500.0, "type": "INCOME", "category": "Consulting", "date": "2024-03-15"},
        headers={**headers, "x-csrf-token": csrf_token},
        cookies={"csrf_token": csrf_token},
    )
    assert resp.status_code == 201
    assert resp.json()["amount"] == 1500.0


@pytest.mark.anyio
async def test_viewer_cannot_create_record(client):
    admin_headers = await _auth_headers(client, "admin@test.com", "AdminPass123!")
    get_resp      = await client.get("/api/v1/records", headers=admin_headers)
    csrf          = get_resp.cookies.get("csrf_token", "test-csrf")

    await client.post(
        "/api/v1/users",
        json={"email": "viewer@test.com", "password": "ViewerPass123!", "role": "VIEWER"},
        headers={**admin_headers, "x-csrf-token": csrf},
        cookies={"csrf_token": csrf},
    )

    viewer_headers = await _auth_headers(client, "viewer@test.com", "ViewerPass123!")
    get_resp2 = await client.get("/api/v1/records", headers=viewer_headers)
    csrf2     = get_resp2.cookies.get("csrf_token", "test-csrf2")

    resp = await client.post(
        "/api/v1/records",
        json={"amount": 100.0, "type": "EXPENSE", "category": "Food", "date": "2024-03-15"},
        headers={**viewer_headers, "x-csrf-token": csrf2},
        cookies={"csrf_token": csrf2},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_csrf_missing_returns_403(client):
    headers = await _auth_headers(client, "admin@test.com", "AdminPass123!")
    resp = await client.post(
        "/api/v1/records",
        json={"amount": 100.0, "type": "INCOME", "category": "Test", "date": "2024-01-01"},
        headers=headers,
    )
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["message"]


@pytest.mark.anyio
async def test_negative_amount_rejected(client):
    headers  = await _auth_headers(client, "admin@test.com", "AdminPass123!")
    get_resp = await client.get("/api/v1/records", headers=headers)
    csrf     = get_resp.cookies.get("csrf_token", "test-csrf")

    resp = await client.post(
        "/api/v1/records",
        json={"amount": -50.0, "type": "INCOME", "category": "Test", "date": "2024-01-01"},
        headers={**headers, "x-csrf-token": csrf},
        cookies={"csrf_token": csrf},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_dashboard_accessible_to_viewer(client):
    viewer_headers = await _auth_headers(client, "viewer@test.com", "ViewerPass123!")
    resp = await client.get("/api/v1/dashboard/summary", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert all(k in body for k in ["total_income", "total_expense", "net_balance"])


@pytest.mark.anyio
async def test_soft_delete_hides_record(client):
    headers  = await _auth_headers(client, "admin@test.com", "AdminPass123!")
    get_resp = await client.get("/api/v1/records", headers=headers)
    csrf     = get_resp.cookies.get("csrf_token", "test-csrf")

    create_resp = await client.post(
        "/api/v1/records",
        json={"amount": 999.0, "type": "EXPENSE", "category": "ToDelete", "date": "2024-06-01"},
        headers={**headers, "x-csrf-token": csrf},
        cookies={"csrf_token": csrf},
    )
    record_id = create_resp.json()["id"]

    del_resp = await client.delete(
        f"/api/v1/records/{record_id}",
        headers={**headers, "x-csrf-token": csrf},
        cookies={"csrf_token": csrf},
    )
    assert del_resp.status_code == 204

    get_by_id = await client.get(f"/api/v1/records/{record_id}", headers=headers)
    assert get_by_id.status_code == 404
