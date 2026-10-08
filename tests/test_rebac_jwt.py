"""Tests for RBAC JWT enrichment at login/refresh time."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from awesome_python_auth import (
    AuthConfig,
    AuthConfigurator,
    InMemoryRolesPermissionsStore,
    InMemoryUserStore,
)
from awesome_python_auth.models import StoredUser
from awesome_python_auth.password_utils import hash_password


def _make_app_with_rbac():
    user_store = InMemoryUserStore()
    rbac_store = InMemoryRolesPermissionsStore()

    config = AuthConfig(
        access_token_secret="a-very-long-secret-that-is-at-least-32-chars!",
        roles_permissions_store=rbac_store,
        cookie_secure=False,
    )
    auth = AuthConfigurator(config, user_store)

    app = FastAPI()
    app.include_router(auth.router())
    return app, user_store, rbac_store, config


class TestJwtRbacEnrichment:
    @pytest.mark.asyncio
    async def test_login_injects_roles_and_permissions(self):
        app, user_store, rbac_store, config = _make_app_with_rbac()

        # Create a user
        user = StoredUser(
            email="user@example.com",
            hashed_password=hash_password("password123"),
        )
        await user_store.create(user)

        # Configure RBAC
        await rbac_store.create_role("editor", permissions=["posts:read", "posts:write"])
        await rbac_store.add_role_to_user(user.id, "editor")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                "/auth/login",
                json={"email": "user@example.com", "password": "password123"},
                headers={"X-Auth-Strategy": "bearer"},
            )

        assert r.status_code == 200
        data = r.json()
        assert "accessToken" in data

        # Decode and verify payload
        import jwt as pyjwt
        payload = pyjwt.decode(
            data["accessToken"],
            config.access_token_secret,
            algorithms=["HS256"],
        )
        assert "editor" in payload.get("roles", [])
        assert "posts:read" in payload.get("permissions", [])
        assert "posts:write" in payload.get("permissions", [])

    @pytest.mark.asyncio
    async def test_no_rbac_store_leaves_token_unchanged(self):
        """Without an RBAC store, tokens are issued without roles/permissions enrichment."""
        user_store = InMemoryUserStore()
        config = AuthConfig(
            access_token_secret="a-very-long-secret-that-is-at-least-32-chars!",
            cookie_secure=False,
        )
        auth = AuthConfigurator(config, user_store)
        app = FastAPI()
        app.include_router(auth.router())

        user = StoredUser(
            email="basic@example.com",
            hashed_password=hash_password("pass"),
        )
        await user_store.create(user)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                "/auth/login",
                json={"email": "basic@example.com", "password": "pass"},
                headers={"X-Auth-Strategy": "bearer"},
            )

        assert r.status_code == 200
        import jwt as pyjwt
        payload = pyjwt.decode(
            r.json()["accessToken"],
            config.access_token_secret,
            algorithms=["HS256"],
        )
        # Roles and permissions should be absent (no store)
        assert payload.get("roles") is None
        assert payload.get("permissions") is None

    @pytest.mark.asyncio
    async def test_tenant_id_in_jwt(self):
        """tenant_id on StoredUser is propagated into the JWT payload."""
        user_store = InMemoryUserStore()
        config = AuthConfig(
            access_token_secret="a-very-long-secret-that-is-at-least-32-chars!",
            cookie_secure=False,
        )
        auth = AuthConfigurator(config, user_store)
        app = FastAPI()
        app.include_router(auth.router())

        user = StoredUser(
            email="tenant@example.com",
            hashed_password=hash_password("pass"),
            tenant_id="tenant-abc",
        )
        await user_store.create(user)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                "/auth/login",
                json={"email": "tenant@example.com", "password": "pass"},
                headers={"X-Auth-Strategy": "bearer"},
            )

        assert r.status_code == 200
        import jwt as pyjwt
        payload = pyjwt.decode(
            r.json()["accessToken"],
            config.access_token_secret,
            algorithms=["HS256"],
        )
        assert payload.get("tenantId") == "tenant-abc"
