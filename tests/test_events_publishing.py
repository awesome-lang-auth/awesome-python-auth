"""Tests for identity event auto-publishing from router and admin router."""

from __future__ import annotations

import asyncio
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from awesome_python_auth import (
    AuthConfig,
    AuthConfigurator,
    InMemoryRolesPermissionsStore,
    InMemoryTenantStore,
    InMemoryUserStore,
)
from awesome_python_auth.admin_router import build_admin_router
from awesome_python_auth.events import AuthEventBus, AuthEventNames, AuthEventPayload
from awesome_python_auth.models import StoredUser
from awesome_python_auth.password_utils import hash_password
from awesome_python_auth.router import _hash_token

SECRET = "a-very-long-secret-key-that-is-at-least-32-chars-long"


def _run(coro):
    return asyncio.run(coro)


def _collect_events(bus: AuthEventBus) -> list[AuthEventPayload]:
    events: list[AuthEventPayload] = []
    bus.on_event("*", lambda p: events.append(p))
    return events


class TestAuthEventNamesParity:
    def test_has_user_email_changed(self):
        assert AuthEventNames.USER_EMAIL_CHANGED == "identity.user.email.changed"


class TestRouterEventPublishing:
    @pytest.fixture()
    def bus(self):
        return AuthEventBus()

    @pytest.fixture()
    def user_store(self):
        return InMemoryUserStore()

    @pytest.fixture()
    def setup_app(self, bus, user_store):
        def _factory(event_bus_override=None, on_oauth_cb=None, on_magic_verify=None, on_sms_verify=None):
            config = AuthConfig(
                api_prefix="/api/auth",
                access_token_secret=SECRET,
                cookie_secure=False,
                cookie_same_site="lax",
                on_oauth_callback=on_oauth_cb,
                on_magic_link_verify=on_magic_verify,
                on_sms_verify=on_sms_verify,
            )
            configurator = AuthConfigurator(config, user_store)
            app = FastAPI()
            app.include_router(configurator.router(event_bus=event_bus_override or bus))
            client = TestClient(app, raise_server_exceptions=False)
            return app, client, config
        return _factory

    def test_login_failed_caps_email_and_extracts_correlation_id(self, setup_app, bus):
        events = _collect_events(bus)
        _, client, _ = setup_app()

        # Malformed email (too long) + valid correlation ID
        long_email = f"{'a' * 400}@x.test"
        res = client.post(
            "/api/auth/login",
            json={"email": long_email, "password": "wrong"},
            headers={"X-Correlation-Id": "corr-123.45:test"},
        )
        assert res.status_code == 401

        # Invalid correlation ID (has spaces / illegal chars)
        res2 = client.post(
            "/api/auth/login",
            json={"email": "nobody@x.test", "password": "wrong"},
            headers={"X-Correlation-Id": "bad id with spaces!"},
        )
        assert res2.status_code == 401

        failed = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGIN_FAILED]
        assert len(failed) == 2

        # Check first event: email cut to 320 chars, valid correlation ID preserved
        assert failed[0]["data"]["method"] == "password"
        assert len(failed[0]["data"]["email"]) == 320
        assert failed[0]["correlationId"] == "corr-123.45:test"

        # Check second event: invalid correlation ID omitted / None
        assert failed[1]["data"]["email"] == "nobody@x.test"
        assert failed[1].get("correlationId") is None

    def test_register_and_login_success(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        _, client, _ = setup_app()

        # 1. Register
        reg_res = client.post(
            "/api/auth/register",
            json={"email": "alice@x.test", "password": "secure-password", "first_name": "Alice"},
            headers={"X-Correlation-Id": "req-reg-1"},
        )
        assert reg_res.status_code == 201

        created = [e for e in events if e["event"] == AuthEventNames.USER_CREATED]
        assert len(created) == 1
        assert created[0]["data"]["email"] == "alice@x.test"
        assert created[0]["data"]["method"] == "default"
        assert created[0]["correlationId"] == "req-reg-1"

        # 2. Login
        login_res = client.post(
            "/api/auth/login",
            json={"email": "alice@x.test", "password": "secure-password"},
            headers={"X-Correlation-Id": "req-login-1"},
        )
        assert login_res.status_code == 200
        assert "access-token" in login_res.cookies

        success = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGIN_SUCCESS]
        assert len(success) == 1
        assert success[0]["userId"] == created[0]["userId"]
        assert success[0]["data"]["method"] == "password"
        assert "sessionId" in success[0]
        assert success[0]["correlationId"] == "req-login-1"

    def test_logout_and_refresh_and_delete_account(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        _, client, _ = setup_app()

        # Register & login
        client.post("/api/auth/register", json={"email": "bob@x.test", "password": "password123"})
        login_res = client.post("/api/auth/login", json={"email": "bob@x.test", "password": "password123"})
        user_id = login_res.json()["sub"]

        # Refresh
        refresh_res = client.post("/api/auth/refresh")
        assert refresh_res.status_code == 200

        rotated = [e for e in events if e["event"] == AuthEventNames.SESSION_ROTATED]
        assert len(rotated) == 1
        assert rotated[0]["userId"] == user_id
        assert "sessionId" in rotated[0]

        # Delete account (authenticated)
        del_res = client.delete("/api/auth/account")
        assert del_res.status_code == 200

        deleted = [e for e in events if e["event"] == AuthEventNames.USER_DELETED]
        assert len(deleted) == 1
        assert deleted[0]["userId"] == user_id

        # Logout
        logout_res = client.post("/api/auth/logout")
        assert logout_res.status_code == 200

        logged_out = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGOUT]
        assert len(logged_out) == 1

    def test_password_and_email_verification_events(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        _, client, _ = setup_app()

        user = StoredUser(
            email="carol@x.test",
            hashed_password=hash_password("old-password"),
            verification_token=_hash_token("verify-token-123"),
            reset_password_token=_hash_token("reset-token-123"),
        )
        _run(user_store.create(user))

        # 1. Verify email
        v_res = client.get("/api/auth/verify-email?token=verify-token-123")
        assert v_res.status_code == 200
        verified = [e for e in events if e["event"] == AuthEventNames.USER_EMAIL_VERIFIED]
        assert len(verified) == 1
        assert verified[0]["userId"] == user.id

        # 2. Reset password
        reset_res = client.post(
            "/api/auth/reset-password",
            json={"token": "reset-token-123", "password": "new-password-1"},
        )
        assert reset_res.status_code == 200
        pwd_changed = [e for e in events if e["event"] == AuthEventNames.USER_PASSWORD_CHANGED]
        assert len(pwd_changed) == 1
        assert pwd_changed[0]["userId"] == user.id

        # 3. Change password (authenticated)
        client.post("/api/auth/login", json={"email": "carol@x.test", "password": "new-password-1"})
        chg_res = client.post(
            "/api/auth/change-password",
            json={"current_password": "new-password-1", "new_password": "new-password-2"},
        )
        assert chg_res.status_code == 200
        pwd_changed2 = [e for e in events if e["event"] == AuthEventNames.USER_PASSWORD_CHANGED]
        assert len(pwd_changed2) == 2

    def test_change_email_confirm_emits_user_email_changed(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        _, client, _ = setup_app()

        user = StoredUser(
            email="dave-old@x.test",
            hashed_password=hash_password("pw-12345"),
            pending_email="dave-new@x.test",
            pending_email_token=_hash_token("email-token-abc"),
        )
        _run(user_store.create(user))

        res = client.post(
            "/api/auth/change-email/confirm",
            json={"token": "email-token-abc"},
            headers={"X-Correlation-Id": "corr-email-chg"},
        )
        assert res.status_code == 200

        email_changed = [e for e in events if e["event"] == AuthEventNames.USER_EMAIL_CHANGED]
        assert len(email_changed) == 1
        assert email_changed[0]["userId"] == user.id
        assert email_changed[0]["data"]["oldEmail"] == "dave-old@x.test"
        assert email_changed[0]["data"]["newEmail"] == "dave-new@x.test"
        assert email_changed[0]["correlationId"] == "corr-email-chg"

    def test_magic_link_and_sms_verify(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        user = StoredUser(email="eva@x.test")
        _run(user_store.create(user))

        async def mock_magic_verify(token, mode):
            return user.id if token == "valid-magic" else None

        async def mock_sms_verify(user_id, temp_token, code, mode):
            return user.id if code == "123456" else None

        _, client, _ = setup_app(on_magic_verify=mock_magic_verify, on_sms_verify=mock_sms_verify)

        # Magic link verify
        ml_res = client.post("/api/auth/magic-link/verify", json={"token": "valid-magic"})
        assert ml_res.status_code == 200
        ml_events = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGIN_SUCCESS and e["data"].get("method") == "magic-link"]
        assert len(ml_events) == 1
        assert ml_events[0]["userId"] == user.id

        # SMS verify
        sms_res = client.post("/api/auth/sms/verify", json={"user_id": user.id, "code": "123456"})
        assert sms_res.status_code == 200
        sms_events = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGIN_SUCCESS and e["data"].get("method") == "sms"]
        assert len(sms_events) == 1
        assert sms_events[0]["userId"] == user.id

    def test_two_factor_auth_events(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        import pyotp
        secret = pyotp.random_base32()
        user = StoredUser(
            email="frank@x.test",
            hashed_password=hash_password("pw-12345"),
            totp_secret=secret,
        )
        _run(user_store.create(user))
        _, client, _ = setup_app()

        # Login to get session
        client.post("/api/auth/login", json={"email": "frank@x.test", "password": "pw-12345"})

        # 1. verify-setup
        code = pyotp.TOTP(secret).now()
        v_res = client.post("/api/auth/2fa/verify-setup", json={"secret": secret, "token": code})
        assert v_res.status_code == 200
        tfa_enabled = [e for e in events if e["event"] == AuthEventNames.USER_2FA_ENABLED]
        assert len(tfa_enabled) == 1
        assert tfa_enabled[0]["userId"] == user.id

        # 2. login with 2FA requirement -> returns tempToken
        login2_res = client.post("/api/auth/login", json={"email": "frank@x.test", "password": "pw-12345"})
        temp_token = login2_res.json()["tempToken"]

        # 3. 2fa/verify
        code2 = pyotp.TOTP(secret).now()
        verify2_res = client.post("/api/auth/2fa/verify", json={"temp_token": temp_token, "totp_code": code2})
        assert verify2_res.status_code == 200
        totp_login = [e for e in events if e["event"] == AuthEventNames.AUTH_LOGIN_SUCCESS and e["data"].get("method") == "totp"]
        assert len(totp_login) == 1
        assert totp_login[0]["userId"] == user.id

        # 4. disable
        dis_res = client.post("/api/auth/2fa/disable")
        assert dis_res.status_code == 200
        tfa_disabled = [e for e in events if e["event"] == AuthEventNames.USER_2FA_DISABLED]
        assert len(tfa_disabled) == 1
        assert tfa_disabled[0]["userId"] == user.id

    def test_oauth_success_and_conflict_events(self, setup_app, bus, user_store):
        events = _collect_events(bus)
        user = StoredUser(email="grace@x.test")
        _run(user_store.create(user))

        async def oauth_cb(provider, request):
            if provider == "conflict_prov":
                raise HTTPException(
                    status_code=409,
                    detail={"error": "OAUTH_ACCOUNT_CONFLICT", "data": {"email": "conflict@x.test", "providerAccountId": "p-1"}},
                )
            return {"userId": user.id, "redirectTo": "/dashboard"}

        _, client, _ = setup_app(on_oauth_cb=oauth_cb)

        # 1. Conflict
        c_res = client.get("/api/auth/oauth/conflict_prov/callback")
        assert c_res.status_code == 409
        conflicts = [e for e in events if e["event"] == AuthEventNames.AUTH_OAUTH_CONFLICT]
        assert len(conflicts) == 1
        assert conflicts[0]["data"]["provider"] == "conflict_prov"
        assert conflicts[0]["data"]["email"] == "conflict@x.test"
        assert conflicts[0]["data"]["providerAccountId"] == "p-1"

        # 2. Success
        s_res = client.get("/api/auth/oauth/google/callback", follow_redirects=False)
        assert s_res.status_code == 302
        assert s_res.headers["location"] == "/dashboard"

        successes = [e for e in events if e["event"] == AuthEventNames.AUTH_OAUTH_SUCCESS]
        assert len(successes) == 1
        assert successes[0]["userId"] == user.id
        assert successes[0]["data"]["provider"] == "google"
        assert successes[0]["data"]["redirectTo"] == "/dashboard"

    def test_throwing_event_listener_does_not_break_auth(self, setup_app, user_store):
        bus = AuthEventBus()

        def broken_listener(p):
            raise RuntimeError("Fatal listener failure!")

        bus.on_event("*", broken_listener)

        _, client, _ = setup_app(event_bus_override=bus)

        # Operation should still succeed completely
        res = client.post(
            "/api/auth/register",
            json={"email": "safe@x.test", "password": "password123"},
        )
        assert res.status_code == 201


class TestAdminRouterEventPublishing:
    def test_role_assigned_and_revoked_with_actor(self):
        bus = AuthEventBus()
        events = _collect_events(bus)

        user_store = InMemoryUserStore()
        rbac_store = InMemoryRolesPermissionsStore()
        admin = StoredUser(
            email="admin@x.test",
            hashed_password=hash_password("adminpw"),
            is_admin=True,
        )
        target = StoredUser(email="target@x.test")
        _run(user_store.create(admin))
        _run(user_store.create(target))

        config = AuthConfig(
            access_token_secret=SECRET,
            cookie_secure=False,
            cookie_same_site="lax",
            roles_permissions_store=rbac_store,
        )
        auth = AuthConfigurator(config, user_store)

        app = FastAPI()
        app.include_router(auth.router(event_bus=bus))
        app.include_router(
            build_admin_router(
                config=config,
                user_store=user_store,
                rbac_store=rbac_store,
                access_policy="is-admin-flag",
                event_bus=bus,
            ),
            prefix="/admin",
        )

        client = TestClient(app)

        # Login as admin
        client.post("/api/auth/login", json={"email": "admin@x.test", "password": "adminpw"})

        # Assign role
        assign_res = client.post(
            f"/admin/api/users/{target.id}/roles",
            json={"role": "editor"},
            headers={"X-Correlation-Id": "admin-op-1"},
        )
        assert assign_res.status_code == 201

        assigned = [e for e in events if e["event"] == AuthEventNames.ROLE_ASSIGNED]
        assert len(assigned) == 1
        assert assigned[0]["userId"] == target.id
        assert assigned[0]["data"]["role"] == "editor"
        assert assigned[0]["data"]["actorId"] == admin.id
        assert assigned[0]["correlationId"] == "admin-op-1"

        # Revoke role
        revoke_res = client.delete(
            f"/admin/api/users/{target.id}/roles/editor",
            headers={"X-Correlation-Id": "admin-op-2"},
        )
        assert revoke_res.status_code == 204

        revoked = [e for e in events if e["event"] == AuthEventNames.ROLE_REVOKED]
        assert len(revoked) == 1
        assert revoked[0]["userId"] == target.id
        assert revoked[0]["data"]["role"] == "editor"
        assert revoked[0]["data"]["actorId"] == admin.id
        assert revoked[0]["correlationId"] == "admin-op-2"
