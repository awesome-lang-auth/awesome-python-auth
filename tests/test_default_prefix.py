"""Default API prefix (/auth) and the built-in UI following the configured prefix.

Every awesome-lang-auth backend serves the API under ``/auth`` and the
built-in UI under ``/auth/ui`` by default (``/auth/ui/login``,
``/auth/ui/auth.js``).  The prefix stays configurable, and the UI moves with it.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from awesome_python_auth import (
    DEFAULT_API_PREFIX,
    AuthConfig,
    AuthConfigurator,
    CsrfMiddleware,
    InMemoryUserStore,
    mount_ui,
    ui_mount_path,
)

SECRET = "a-very-long-secret-key-that-is-at-least-32-chars-long"


def _auth_js_api_prefix(page_path: str) -> str:
    """The rule auth.js applies to the page URL to find the API prefix."""
    return page_path.split("/ui/")[0] if "/ui/" in page_path else "/auth"


def _app(api_prefix: str | None = None, **config_kwargs) -> tuple[FastAPI, AuthConfig, str]:
    kwargs = {"access_token_secret": SECRET, "cookie_secure": False, **config_kwargs}
    if api_prefix is not None:
        kwargs["api_prefix"] = api_prefix
    config = AuthConfig(**kwargs)
    app = FastAPI()
    if api_prefix is None:
        app.add_middleware(CsrfMiddleware, cookie_secure=False)
    else:
        app.add_middleware(CsrfMiddleware, api_prefix=api_prefix, cookie_secure=False)
    app.include_router(AuthConfigurator(config, InMemoryUserStore()).router())
    ui_path = mount_ui(app, config)
    return app, config, ui_path


def _register_login_me(client: TestClient, prefix: str) -> dict:
    creds = {"email": "ada@example.com", "password": "Pass1234!"}
    resp = client.post(f"{prefix}/register", json={**creds, "firstName": "Ada"})
    assert resp.status_code == 201, resp.text
    resp = client.post(f"{prefix}/login", json=creds)
    assert resp.status_code == 200, resp.text
    assert "access-token" in resp.cookies
    resp = client.get(f"{prefix}/me")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _ssr_config(html: str) -> dict:
    match = re.search(r"window\.__AUTH_CONFIG__ = (\{.*?\});</script>", html)
    assert match, "SSR bootstrap script missing"
    return json.loads(match.group(1))


class TestDefaults:
    def test_default_api_prefix_is_auth(self):
        assert DEFAULT_API_PREFIX == "/auth"
        assert AuthConfig().api_prefix == "/auth"

    def test_ui_mount_path(self):
        assert ui_mount_path() == "/auth/ui"
        assert ui_mount_path("/api/auth") == "/api/auth/ui"
        assert ui_mount_path("/auth/") == "/auth/ui"

    def test_router_routes_are_under_auth(self):
        router = AuthConfigurator(AuthConfig(access_token_secret=SECRET), InMemoryUserStore()).router()
        paths = {route.path for route in router.routes}
        assert {"/auth/login", "/auth/register", "/auth/me", "/auth/ui/config"} <= paths
        assert not any(p.startswith("/api/auth") for p in paths)


class TestDefaultPrefixApp:
    def test_api_flow_under_auth(self):
        app, _, _ = _app()
        client = TestClient(app)
        me = _register_login_me(client, "/auth")
        assert me["email"] == "ada@example.com"
        assert client.post("/api/auth/login", json={"email": "x", "password": "y"}).status_code == 404

    def test_ui_is_mounted_under_auth_ui(self):
        app, _, ui_path = _app()
        assert ui_path == "/auth/ui"
        client = TestClient(app)
        assert client.get("/auth/ui/auth.js").status_code == 200
        login = client.get("/auth/ui/login")
        assert login.status_code == 200
        assert 'src="auth.js?v=2"' in login.text

    def test_page_url_and_ssr_config_agree_on_the_prefix(self):
        app, config, _ = _app()
        login = TestClient(app).get("/auth/ui/login")
        assert _ssr_config(login.text)["apiPrefix"] == "/auth"
        assert _auth_js_api_prefix("/auth/ui/login") == config.api_prefix

    def test_router_keeps_ui_config(self):
        # The auth router is included before the UI is mounted, so it still
        # answers GET <prefix>/ui/config with the 1.x payload.
        app, _, _ = _app(ui_config={"theme": "dark"})
        resp = TestClient(app).get("/auth/ui/config")
        assert resp.status_code == 200
        assert resp.json() == {"theme": "dark"}


class TestCustomPrefixApp:
    PREFIX = "/api/auth"

    def test_api_flow_moves(self):
        app, _, _ = _app(self.PREFIX)
        client = TestClient(app)
        me = _register_login_me(client, self.PREFIX)
        assert me["email"] == "ada@example.com"
        assert client.post("/auth/login", json={"email": "x", "password": "y"}).status_code == 404

    def test_ui_moves(self):
        app, _, ui_path = _app(self.PREFIX)
        assert ui_path == "/api/auth/ui"
        client = TestClient(app)
        assert client.get("/api/auth/ui/auth.js").status_code == 200
        assert client.get("/api/auth/ui/login").status_code == 200
        assert client.get("/auth/ui/auth.js").status_code == 404
        assert client.get("/auth/ui/login").status_code == 404

    def test_page_url_and_ssr_config_agree_on_the_prefix(self):
        app, config, _ = _app(self.PREFIX)
        login = TestClient(app).get("/api/auth/ui/login")
        assert _ssr_config(login.text)["apiPrefix"] == self.PREFIX
        assert _auth_js_api_prefix("/api/auth/ui/login") == config.api_prefix


class TestCsrfPrefix:
    def _client(self, **middleware_kwargs) -> TestClient:
        app = FastAPI()
        app.add_middleware(CsrfMiddleware, cookie_secure=False, **middleware_kwargs)

        @app.post("/auth/profile")
        async def profile():
            return {"ok": True}

        @app.post("/authors")
        async def authors():
            return {"ok": True}

        @app.post("/api/auth/profile")
        async def old_profile():
            return {"ok": True}

        return TestClient(app)

    def test_default_prefix_is_enforced(self):
        client = self._client()
        assert client.post("/auth/profile").status_code == 403
        # Not under the default prefix any more.
        assert client.post("/api/auth/profile").status_code == 200

    def test_prefix_matches_whole_path_segments(self):
        assert self._client().post("/authors").status_code == 200

    @pytest.mark.parametrize("prefix", ["/api/auth", "/api/auth/"])
    def test_custom_prefix(self, prefix):
        client = self._client(api_prefix=prefix)
        assert client.post("/api/auth/profile").status_code == 403
        assert client.post("/auth/profile").status_code == 200

    def test_valid_token_passes_under_default_prefix(self):
        client = self._client()
        client.get("/auth/anything")  # sets the csrf-token cookie
        token = client.cookies.get("csrf-token")
        assert token
        assert client.post("/auth/profile", headers={"X-CSRF-Token": token}).status_code == 200
