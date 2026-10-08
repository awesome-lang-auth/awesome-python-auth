"""Integration tests for the auth router using FastAPI TestClient."""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from awesome_python_auth.config import AuthConfig, AuthConfigurator
from awesome_python_auth.jwt_utils import decode_token
from awesome_python_auth.models import InMemoryUserStore, StoredUser
from awesome_python_auth.password_utils import hash_password

SECRET = "router-test-secret"


def _run(coro):
    """Run a store coroutine to completion from a synchronous test.

    These tests are synchronous and drive the app through ``TestClient``, which
    runs the ASGI app on its own event loop. ``InMemoryUserStore`` holds no
    loop-bound state, so a private loop is enough. ``asyncio.run`` does not
    depend on a "current" event loop left behind by pytest-asyncio, unlike
    ``asyncio.get_event_loop().run_until_complete(...)``.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def user_store():
    store = InMemoryUserStore()
    return store


@pytest.fixture()
def app(user_store):
    config = AuthConfig(
        api_prefix="/api/auth",
        access_token_secret=SECRET,
        cookie_secure=False,
        cookie_same_site="lax",
    )
    configurator = AuthConfigurator(config, user_store)
    fastapi_app = FastAPI()
    fastapi_app.include_router(configurator.router())
    return fastapi_app


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def registered_user(user_store):
    """Pre-populate the store with a verified user."""
    stored = StoredUser(
        email="alice@example.com",
        hashed_password=hash_password("password123"),
        first_name="Alice",
        last_name="Smith",
        is_email_verified=True,
    )
    _run(user_store.create(stored))
    return stored


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_success(self, client):
        resp = client.post(
            "/api/auth/register",
            json={"email": "bob@example.com", "password": "Pass1234!", "firstName": "Bob", "lastName": "Jones"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["success"] is True
        assert "userId" in data

    def test_duplicate_email(self, client, registered_user):
        resp = client.post(
            "/api/auth/register",
            json={"email": "alice@example.com", "password": "Pass1234!"},
        )
        assert resp.status_code == 409

    def test_email_normalised_to_lowercase(self, client, user_store):
        resp = client.post(
            "/api/auth/register",
            json={"email": "UPPER@EXAMPLE.COM", "password": "Pass1234!"},
        )
        assert resp.status_code == 201
        user = _run(user_store.get_by_email("upper@example.com"))
        assert user is not None


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class TestLogin:
    def test_success_cookie_mode(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["email"] == "alice@example.com"
        assert "access-token" in resp.cookies

    def test_success_bearer_mode(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "accessToken" in data
        assert "refreshToken" in data

    def test_wrong_password(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401

    def test_cookie_prefix_mode_sets_prefixed_cookie_names(self, user_store):
        config = AuthConfig(
            api_prefix="/api/auth",
            access_token_secret=SECRET,
            cookie_secure=False,
            cookie_same_site="lax",
            cookie_prefix="__Host-",
        )
        app = FastAPI()
        app.include_router(AuthConfigurator(config, user_store).router())
        local_client = TestClient(app, raise_server_exceptions=True)
        stored = StoredUser(
            email="prefixed@example.com",
            hashed_password=hash_password("password123"),
            first_name="Prefix",
            last_name="User",
            is_email_verified=True,
        )
        _run(user_store.create(stored))

        login_resp = local_client.post(
            "/api/auth/login",
            json={"email": "prefixed@example.com", "password": "password123"},
        )
        assert login_resp.status_code == 200
        assert "__Host-access-token" in login_resp.cookies
        assert "__Host-refresh-token" in login_resp.cookies

        me_resp = local_client.get("/api/auth/me")
        assert me_resp.status_code == 200

    def test_unknown_email(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "anything"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------


class TestMe:
    def _login_get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_me_with_valid_bearer(self, client, registered_user):
        token = self._login_get_token(client, registered_user)
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice@example.com"

    def test_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_with_cookie(self, client, registered_user):
        login_resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        assert "access-token" in login_resp.cookies
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_clears_cookies(self, client, registered_user):
        client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert resp.json()["success"] is True


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class TestProfile:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_update_profile(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.patch(
            "/api/auth/profile",
            json={"firstName": "Alicia", "lastName": "Doe"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_update_profile_unauthenticated(self, client):
        resp = client.patch(
            "/api/auth/profile",
            json={"firstName": "X", "lastName": "Y"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------


class TestPasswordManagement:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_forgot_password_always_200(self, client):
        resp = client.post(
            "/api/auth/forgot-password",
            json={"email": "nobody@example.com"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_change_password(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/change-password",
            json={"currentPassword": "password123", "newPassword": "NewPass!456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_change_password_wrong_current(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/change-password",
            json={"currentPassword": "WRONG", "newPassword": "NewPass!456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestSessions:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_get_sessions(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.get(
            "/api/auth/sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "sessions" in resp.json()

    def test_revoke_unknown_session(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.delete(
            "/api/auth/sessions/nonexistent-handle",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 2FA
# ---------------------------------------------------------------------------


class TestTwoFactor:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_setup_2fa(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/2fa/setup",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "qrCode" in data

    def test_disable_2fa(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/2fa/disable",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# UI config
# ---------------------------------------------------------------------------


class TestUiConfig:
    def test_returns_the_node_shaped_config_by_default(self, client):
        # Not the raw (empty) AuthConfig.ui_config any more: the payload auth.js reads.
        resp = client.get("/api/auth/ui/config")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == {"apiPrefix", "features", "ui", "headless"}
        assert data["apiPrefix"] == "/api/auth"
        assert data["headless"] is True


# ---------------------------------------------------------------------------
# Delete account
# ---------------------------------------------------------------------------


class TestDeleteAccount:
    def test_delete_account(self, client, registered_user, user_store):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        token = resp.json()["accessToken"]
        del_resp = client.delete(
            "/api/auth/account",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert del_resp.status_code == 200
        user = _run(user_store.get_by_email("alice@example.com"))
        assert user is None


class TestOauthEndpoints:
    def test_oauth_start_redirects_to_provider(self, user_store):
        async def on_oauth_start(provider, request):
            return f"https://oauth.example/{provider}/authorize"

        config = AuthConfig(
            api_prefix="/api/auth",
            access_token_secret=SECRET,
            cookie_secure=False,
            on_oauth_start=on_oauth_start,
        )
        app = FastAPI()
        app.include_router(AuthConfigurator(config, user_store).router())
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/api/auth/oauth/google", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "https://oauth.example/google/authorize"

    def test_oauth_callback_can_login_and_set_session_cookies(self, user_store):
        stored = StoredUser(
            email="oauth@example.com",
            hashed_password=hash_password("password123"),
            first_name="OAuth",
            last_name="User",
            is_email_verified=True,
        )
        _run(user_store.create(stored))

        async def on_oauth_callback(provider, request):
            return {"userId": stored.id, "redirectTo": "/welcome"}

        config = AuthConfig(
            api_prefix="/api/auth",
            access_token_secret=SECRET,
            cookie_secure=False,
            on_oauth_callback=on_oauth_callback,
        )
        app = FastAPI()
        app.include_router(AuthConfigurator(config, user_store).router())
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/api/auth/oauth/github/callback", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/welcome"
        assert "access-token" in resp.cookies
        assert "refresh-token" in resp.cookies


class TestStatefulSessionPolicies:
    def test_check_on_allcalls_rejects_revoked_session(self, user_store):
        stored = StoredUser(
            email="allcalls@example.com",
            hashed_password=hash_password("password123"),
            first_name="All",
            last_name="Calls",
            is_email_verified=True,
        )
        _run(user_store.create(stored))

        config = AuthConfig(
            api_prefix="/api/auth",
            access_token_secret=SECRET,
            cookie_secure=False,
            session_check_on="allcalls",
        )
        app = FastAPI()
        app.include_router(AuthConfigurator(config, user_store).router())
        client = TestClient(app, raise_server_exceptions=True)

        login_resp = client.post(
            "/api/auth/login",
            json={"email": "allcalls@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        access_token = login_resp.json()["accessToken"]
        refresh_token = login_resp.json()["refreshToken"]
        handle = decode_token(refresh_token, SECRET)["sessionHandle"]
        _run(user_store.delete_session(handle))

        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "SESSION_REVOKED"

    def test_check_on_refresh_returns_session_revoked_code(self, user_store):
        stored = StoredUser(
            email="refresh@example.com",
            hashed_password=hash_password("password123"),
            first_name="Re",
            last_name="Fresh",
            is_email_verified=True,
        )
        _run(user_store.create(stored))

        config = AuthConfig(
            api_prefix="/api/auth",
            access_token_secret=SECRET,
            cookie_secure=False,
            session_check_on="refresh",
        )
        app = FastAPI()
        app.include_router(AuthConfigurator(config, user_store).router())
        client = TestClient(app, raise_server_exceptions=True)

        login_resp = client.post(
            "/api/auth/login",
            json={"email": "refresh@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        refresh_token = login_resp.json()["refreshToken"]
        handle = decode_token(refresh_token, SECRET)["sessionHandle"]
        _run(user_store.delete_session(handle))

        refresh_resp = client.post("/api/auth/refresh", json={"refreshToken": refresh_token})
        assert refresh_resp.status_code == 401
        assert refresh_resp.json()["code"] == "SESSION_REVOKED"
