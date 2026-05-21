"""API integration tests — auth and health endpoints."""
import pytest


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_register(client):
    resp = client.post("/api/v1/auth/register", json={
        "email": "new@test.dev", "username": "newuser", "password": "pass1234"
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login(client):
    client.post("/api/v1/auth/register", json={
        "email": "login@test.dev", "username": "loginuser", "password": "pass1234"
    })
    resp = client.post("/api/v1/auth/login", data={
        "username": "login@test.dev", "password": "pass1234"
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password(client):
    client.post("/api/v1/auth/register", json={
        "email": "wp@test.dev", "username": "wpuser", "password": "correct"
    })
    resp = client.post("/api/v1/auth/login", data={"username": "wp@test.dev", "password": "wrong"})
    assert resp.status_code == 401


def test_me_unauthenticated(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.wrong-signature",
        "",
    ],
)
def test_invalid_token_is_401_not_403(client, token):
    """
    An unusable token must be 401, not 403.

    The frontend's axios interceptor triggers logout-and-redirect on 401 only
    (frontend/src/api/client.ts). This handler used to return 403, so an expired
    session left the user watching every request fail with no way back to login.
    401 is also the correct semantic: 403 means authenticated-but-forbidden.
    """
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_token_with_non_uuid_subject_is_401_not_500(client):
    """A signed token whose `sub` is not a UUID is malformed input, not a crash."""
    from app.api.v1.auth import create_access_token

    resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {create_access_token('not-a-uuid')}"},
    )
    assert resp.status_code == 401


def test_me_authenticated(auth_client):
    resp = auth_client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert "email" in resp.json()


def test_repos_list_empty(auth_client):
    resp = auth_client.get("/api/v1/repositories")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_reviews_list_empty(auth_client):
    resp = auth_client.get("/api/v1/reviews")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_security_summary(auth_client):
    resp = auth_client.get("/api/v1/security/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_open" in data
    assert "critical_open" in data


def test_model_status(auth_client):
    resp = auth_client.get("/api/v1/model/status")
    assert resp.status_code == 200
    assert "backend" in resp.json()
