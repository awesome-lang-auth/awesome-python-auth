"""auth.js and /ui/config come with the auth router; the pages stay optional.

Every awesome-lang-auth backend serves the browser runtime at
``<prefix>/ui/auth.js`` (``/auth/ui/auth.js`` by default), next to a
node-shaped ``<prefix>/ui/config``, as soon as its auth router is mounted.  The
built-in pages are optional (``mount_ui``): without them ``/ui/login`` is 404
while ``auth.js`` is 200 and ``/ui/config`` reports ``headless: true``, as in
awesome-node-auth's headless mode.  A UI mounted at ``<prefix>/ui`` serves all
of ``<prefix>/ui`` itself, whatever the order it and the router were added in.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

from awesome_python_auth import (
    AuthConfig,
    AuthConfigurator,
    InMemoryUserStore,
    SettingsStore,
    build_ui_router,
    mount_ui,
)

SECRET = "a-very-long-secret-key-that-is-at-least-32-chars-long"
BUNDLED_AUTH_JS = (
    Path(__file__).resolve().parent.parent / "awesome_python_auth" / "ui_assets" / "auth.js"
).read_bytes()
NODE_CONFIG_KEYS = {"apiPrefix", "features", "ui", "headless"}
NODE_FEATURE_KEYS = {
    "register", "magicLink", "sms", "google", "github", "forgotPassword", "verifyEmail", "twoFactor",
}
ORDERS = ["router-first", "ui-first"]
PREFIXES = [None, "/api/auth"]


class _DictSettingsStore(SettingsStore):
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data = dict(data or {})

    async def get(self, key: str) -> Any:
        return self._data.get(key)

    async def set(self, key: str, value: Any) -> None:
        self._data[key] = value


def _config(prefix: str | None = None, **kwargs) -> AuthConfig:
    if prefix is not None:
        kwargs["api_prefix"] = prefix
    return AuthConfig(access_token_secret=SECRET, cookie_secure=False, **kwargs)


def _router(config: AuthConfig, **router_kwargs):
    return AuthConfigurator(config, InMemoryUserStore()).router(**router_kwargs)


def _router_only(prefix: str | None = None, **config_kwargs) -> tuple[TestClient, str]:
    config = _config(prefix, **config_kwargs)
    app = FastAPI()
    app.include_router(_router(config))
    return TestClient(app), config.api_prefix


def _with_ui(order: str, config: AuthConfig, mount, **router_kwargs) -> TestClient:
    """Include the auth router and call *mount(app)*, in *order*."""
    app = FastAPI()
    if order == "router-first":
        app.include_router(_router(config, **router_kwargs))
        mount(app)
    else:
        mount(app)
        app.include_router(_router(config, **router_kwargs))
    return TestClient(app)


def _ssr_config(html: str) -> dict:
    match = re.search(r"window\.__AUTH_CONFIG__ = (\{.*?\});</script>", html)
    assert match, "SSR bootstrap script missing"
    return json.loads(match.group(1))


def _custom_assets(tmp_path: Path, *, auth_js: bytes | None) -> Path:
    assets = tmp_path / "custom-ui"
    assets.mkdir()
    (assets / "login.html").write_text(
        '<html><head><title>x</title></head><body>custom login'
        '<script src="auth.js?v=2"></script></body></html>',
        encoding="utf-8",
    )
    if auth_js is not None:
        (assets / "auth.js").write_bytes(auth_js)
    return assets


class TestRouterOnly:
    """No UI mounted: what ``app.include_router(configurator.router())`` serves."""

    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_auth_js_is_served(self, prefix):
        client, p = _router_only(prefix)
        resp = client.get(f"{p}/ui/auth.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers["content-type"]
        assert resp.content == BUNDLED_AUTH_JS

    def test_default_route_is_auth_ui_auth_js(self):
        client, p = _router_only()
        assert p == "/auth"
        assert client.get("/auth/ui/auth.js").status_code == 200

    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_config_is_node_shaped_and_headless(self, prefix):
        client, p = _router_only(prefix)
        resp = client.get(f"{p}/ui/config")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == NODE_CONFIG_KEYS
        assert set(data["features"]) == NODE_FEATURE_KEYS
        assert data["apiPrefix"] == p
        # No pages here: auth.js must not send the browser to a missing login page.
        assert data["headless"] is True

    @pytest.mark.parametrize("prefix", PREFIXES)
    @pytest.mark.parametrize("page", ["login", "register", "forgot-password", "base.css", ""])
    def test_pages_are_not_served(self, prefix, page):
        client, p = _router_only(prefix)
        assert client.get(f"{p}/ui/{page}").status_code == 404

    def test_custom_prefix_moves_auth_js_and_config(self):
        client, _ = _router_only("/api/auth")
        assert client.get("/api/auth/ui/auth.js").status_code == 200
        assert client.get("/api/auth/ui/config").status_code == 200
        assert client.get("/auth/ui/auth.js").status_code == 404
        assert client.get("/auth/ui/config").status_code == 404

    def test_default_prefix_serves_nothing_under_the_1x_prefix(self):
        client, _ = _router_only()
        assert client.get("/api/auth/ui/auth.js").status_code == 404
        assert client.get("/api/auth/ui/config").status_code == 404

    def test_config_reports_ui_config(self):
        client, p = _router_only(
            ui_config={"features": {"google": True}, "ui": {"siteName": "Acme", "primaryColor": "#123456"}}
        )
        data = client.get(f"{p}/ui/config").json()
        assert data["features"]["google"] is True
        assert data["ui"]["siteName"] == "Acme"
        assert data["ui"]["primaryColor"] == "#123456"

    def test_settings_store_ui_config_replaces_config_ui_config(self):
        config = _config(ui_config={"ui": {"siteName": "From config"}})
        store = _DictSettingsStore({"ui_config": {"ui": {"siteName": "From store"}}})
        app = FastAPI()
        app.include_router(_router(config, settings_store=store))
        data = TestClient(app).get("/auth/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
        assert data["ui"]["siteName"] == "From store"

    def test_empty_settings_store_falls_back_to_config_ui_config(self):
        config = _config(ui_config={"ui": {"siteName": "From config"}})
        app = FastAPI()
        app.include_router(_router(config, settings_store=_DictSettingsStore()))
        assert TestClient(app).get("/auth/ui/config").json()["ui"]["siteName"] == "From config"

    def test_router_on_register_enables_the_register_feature(self):
        async def on_register(user):
            return user

        config = _config()
        app = FastAPI()
        app.include_router(_router(config, on_register=on_register))
        assert TestClient(app).get("/auth/ui/config").json()["features"]["register"] is True
        client, _ = _router_only()
        assert client.get("/auth/ui/config").json()["features"]["register"] is False

    def test_each_route_is_registered_once(self):
        paths = [route.path for route in _router(_config()).routes]
        assert paths.count("/auth/ui/auth.js") == 1
        assert paths.count("/auth/ui/config") == 1

    def test_openapi_lists_config_not_auth_js(self):
        app = FastAPI()
        app.include_router(_router(_config()))
        schema_paths = app.openapi()["paths"]
        assert "get" in schema_paths["/auth/ui/config"]
        assert "/auth/ui/auth.js" not in schema_paths

    def test_router_included_under_an_extra_prefix(self):
        app = FastAPI()
        app.include_router(_router(_config()), prefix="/v1")
        client = TestClient(app)
        assert client.get("/v1/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/v1/auth/ui/config").json()["headless"] is True

    def test_a_root_mount_does_not_hide_auth_js(self, tmp_path):
        # A catch-all mount at "/" (an SPA) is not a UI at <prefix>/ui.
        (tmp_path / "index.html").write_text("spa", encoding="utf-8")
        app = FastAPI()
        app.include_router(_router(_config()))
        app.mount("/", StaticFiles(directory=str(tmp_path), html=True), name="spa")
        client = TestClient(app)
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/auth/ui/config").json()["headless"] is True


class TestWithPages:
    """``mount_ui`` (or a hand-mounted ``build_ui_router``) at ``<prefix>/ui``."""

    @pytest.mark.parametrize("order", ORDERS)
    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_pages_auth_js_and_config(self, order, prefix):
        config = _config(prefix)
        p = config.api_prefix
        client = _with_ui(order, config, lambda app: mount_ui(app, config))
        login = client.get(f"{p}/ui/login")
        assert login.status_code == 200
        assert 'src="auth.js?v=2"' in login.text
        assert _ssr_config(login.text)["apiPrefix"] == p
        js = client.get(f"{p}/ui/auth.js")
        assert js.status_code == 200
        assert js.content == BUNDLED_AUTH_JS
        cfg = client.get(f"{p}/ui/config").json()
        assert set(cfg) == NODE_CONFIG_KEYS
        assert cfg["apiPrefix"] == p
        # Answered by the mounted UI, which serves the pages: not headless.
        assert cfg["headless"] is False

    @pytest.mark.parametrize("order", ORDERS)
    def test_mounted_ui_serves_its_own_auth_js(self, order, tmp_path):
        # A custom auth.js proves the mount answers, not the router.
        assets = _custom_assets(tmp_path, auth_js=b"/* custom runtime */\n")
        config = _config()
        client = _with_ui(order, config, lambda app: mount_ui(app, config, ui_assets_dir=assets))
        assert client.get("/auth/ui/auth.js").content == b"/* custom runtime */\n"
        assert "custom login" in client.get("/auth/ui/login").text

    @pytest.mark.parametrize("order", ORDERS)
    def test_mounted_ui_serves_its_own_config(self, order):
        store = _DictSettingsStore({"ui_config": {"ui": {"siteName": "Mounted UI"}}})
        config = _config()
        client = _with_ui(order, config, lambda app: mount_ui(app, config, settings_store=store))
        cfg = client.get("/auth/ui/config").json()
        assert cfg["ui"]["siteName"] == "Mounted UI"
        assert cfg["headless"] is False
        login = client.get("/auth/ui/login")
        assert _ssr_config(login.text)["ui"]["siteName"] == "Mounted UI"

    @pytest.mark.parametrize("order", ORDERS)
    def test_headless_mount(self, order):
        config = _config()
        client = _with_ui(order, config, lambda app: mount_ui(app, config, headless=True))
        assert client.get("/auth/ui/login").status_code == 404
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/auth/ui/config").json()["headless"] is True

    @pytest.mark.parametrize("order", ORDERS)
    def test_hand_mounted_build_ui_router(self, order):
        # 1.x style: app.mount("/auth/ui", build_ui_router(...)) next to the router.
        config = _config()
        client = _with_ui(
            order, config, lambda app: app.mount("/auth/ui", build_ui_router(config=config))
        )
        assert client.get("/auth/ui/login").status_code == 200
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/auth/ui/config").json()["headless"] is False

    def test_ui_mounted_under_another_path_leaves_the_router_alone(self):
        # 1.x docstring layout: API under /api/auth, UI by hand at /auth/ui.
        config = _config("/api/auth")
        app = FastAPI()
        app.include_router(_router(config))
        app.mount("/auth/ui", build_ui_router(config=config))
        client = TestClient(app)
        assert client.get("/api/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/api/auth/ui/config").json()["headless"] is True
        assert client.get("/api/auth/ui/login").status_code == 404
        assert client.get("/auth/ui/login").status_code == 200
        assert client.get("/auth/ui/config").json()["headless"] is False

    @pytest.mark.parametrize("headless", [False, True])
    def test_custom_assets_without_auth_js_fall_back_to_the_bundled_one(self, headless, tmp_path):
        assets = _custom_assets(tmp_path, auth_js=None)
        config = _config()
        client = _with_ui(
            "router-first",
            config,
            lambda app: mount_ui(app, config, ui_assets_dir=assets, headless=headless),
        )
        resp = client.get("/auth/ui/auth.js")
        assert resp.status_code == 200
        assert resp.content == BUNDLED_AUTH_JS
