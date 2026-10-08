"""auth.js and /ui/config come with the auth router; the pages stay optional.

Every awesome-lang-auth backend serves the browser runtime at
``<prefix>/ui/auth.js`` (``/auth/ui/auth.js`` by default), next to a
node-shaped ``<prefix>/ui/config``, as soon as its auth router is mounted.  The
built-in pages are optional (``mount_ui``): without them ``/ui/login`` is 404
while ``auth.js`` is 200.  ``/ui/config`` reports the configured
``ui_config["headless"]`` (``false`` unless set), as awesome-node-auth reports
``ui.headless``.  A UI mounted at ``<prefix>/ui`` serves all of
``<prefix>/ui`` itself, whatever the order it and the router were added in.
The document is awesome-node-auth's, byte for byte with the defaults, and its
``apiPrefix`` is the prefix the request came through.
"""

from __future__ import annotations

import hashlib
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
from awesome_python_auth.mailer import MailerConfig

SECRET = "a-very-long-secret-key-that-is-at-least-32-chars-long"
BUNDLED_AUTH_JS = (
    Path(__file__).resolve().parent.parent / "awesome_python_auth" / "ui_assets" / "auth.js"
).read_bytes()
# awesome-node-auth's /ui/config keys, in its order.
NODE_CONFIG_ORDER = ["apiPrefix", "features", "ui", "translations", "lang", "headless"]
NODE_CONFIG_KEYS = set(NODE_CONFIG_ORDER)
NODE_FEATURE_KEYS = {
    "register", "magicLink", "sms", "google", "github", "forgotPassword", "verifyEmail", "twoFactor",
}
# sha256 of awesome-node-auth's GET <prefix>/ui/config body with nothing configured
# but the prefix and ui.headless, measured on 1.10.8 (ui.enabled) and on #38 (ui
# unset); the two are byte-identical.  The 309-byte default document:
NODE_DEFAULT_CONFIG = (
    b'{"apiPrefix":"/auth","features":{"register":false,"magicLink":false,"sms":false,'
    b'"google":false,"github":false,"forgotPassword":false,"verifyEmail":false,'
    b'"twoFactor":false},"ui":{"primaryColor":"#4a90d9","secondaryColor":"#6c757d",'
    b'"siteName":"Awesome Node Auth"},"translations":{},"lang":"en","headless":false}'
)
NODE_CONFIG_SHA256 = {
    ("/auth", False): "50746e3028e02348edc5c197fbd0a9b575a3f2353924bb658fc764014754177f",
    ("/auth", True): "8fc354481ca632ee54ca72c0ab2c2db4178735fc1db906355da1d840fe3d5210",
    ("/api/auth", False): "50a330b8bca2e24625340ae643d540f0d178e38f5c75a2bffe1c1ea29aa90171",
    ("/api/auth", True): "02b46012e8391668947433a569eb99e8fa19904f23a54720fc00b037000642c1",
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
    def test_config_is_node_shaped(self, prefix):
        client, p = _router_only(prefix)
        resp = client.get(f"{p}/ui/config")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == NODE_CONFIG_KEYS
        assert set(data["features"]) == NODE_FEATURE_KEYS
        assert data["apiPrefix"] == p
        # The configured flag, false by default, as on awesome-node-auth: not
        # forced to true because the pages are not mounted.
        assert data["headless"] is False

    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_config_reports_the_configured_headless_flag(self, prefix):
        client, p = _router_only(prefix, ui_config={"headless": True})
        data = client.get(f"{p}/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
        assert data["headless"] is True

    def test_settings_store_headless_flag(self):
        config = _config(ui_config={"headless": False})
        store = _DictSettingsStore({"ui_config": {"headless": True}})
        app = FastAPI()
        app.include_router(_router(config, settings_store=store))
        data = TestClient(app).get("/auth/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
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
            ui_config={
                "features": {"google": True},
                "ui": {"siteName": "Acme", "primaryColor": "#123456", "logoUrl": "/logo.svg"},
            }
        )
        data = client.get(f"{p}/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
        assert data["features"]["google"] is True
        assert data["ui"] == {
            "primaryColor": "#123456",
            "secondaryColor": "#6c757d",
            "logoUrl": "/logo.svg",
            "siteName": "Acme",
        }

    def test_settings_store_ui_config_replaces_config_ui_config(self):
        config = _config(ui_config={"ui": {"siteName": "From config"}})
        store = _DictSettingsStore({"ui_config": {"ui": {"siteName": "From store"}}})
        app = FastAPI()
        app.include_router(_router(config, settings_store=store))
        data = TestClient(app).get("/auth/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
        assert data["ui"]["siteName"] == "From store"

    @pytest.mark.parametrize(
        "stored",
        [None, {}, "not a dict", ["x"]],
        ids=["missing", "empty", "string", "list"],
    )
    def test_settings_store_without_a_document_falls_back_to_config_ui_config(self, stored):
        # As in 1.x, an empty stored document does not replace AuthConfig.ui_config;
        # neither does a value that is not a dict.
        config = _config(ui_config={"ui": {"siteName": "From config"}})
        store = _DictSettingsStore({} if stored is None else {"ui_config": stored})
        app = FastAPI()
        app.include_router(_router(config, settings_store=store))
        data = TestClient(app).get("/auth/ui/config").json()
        assert set(data) == NODE_CONFIG_KEYS
        assert data["ui"]["siteName"] == "From config"

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
        # apiPrefix is where the request reached the router, as node's req.baseUrl:
        # auth.js merges it over the page's init({apiPrefix}) and calls it.
        app = FastAPI()
        app.include_router(_router(_config()), prefix="/v1")
        client = TestClient(app)
        assert client.get("/v1/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        data = client.get("/v1/auth/ui/config").json()
        assert data["apiPrefix"] == "/v1/auth"
        assert data["headless"] is False
        assert client.get("/auth/ui/config").status_code == 404

    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_router_in_a_sub_application(self, prefix):
        config = _config(prefix)
        sub = FastAPI()
        sub.include_router(_router(config))
        app = FastAPI()
        app.mount("/svc", sub)
        client = TestClient(app)
        assert client.get(f"/svc{config.api_prefix}/ui/auth.js").content == BUNDLED_AUTH_JS
        data = client.get(f"/svc{config.api_prefix}/ui/config").json()
        assert data["apiPrefix"] == f"/svc{config.api_prefix}"

    def test_server_root_path_is_part_of_api_prefix(self):
        # Behind a proxy that strips /svc (uvicorn --root-path /svc) the browser
        # calls /svc/auth/..., so that is the prefix auth.js has to use.
        app = FastAPI()
        app.include_router(_router(_config()))
        client = TestClient(app, root_path="/svc")
        assert client.get("/auth/ui/config").json()["apiPrefix"] == "/svc/auth"

    def test_head_auth_js(self):
        client, p = _router_only()
        resp = client.head(f"{p}/ui/auth.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers["content-type"]
        assert resp.headers["content-length"] == str(len(BUNDLED_AUTH_JS))
        assert resp.content == b""

    def test_a_root_mount_does_not_hide_auth_js(self, tmp_path):
        # A catch-all mount at "/" (an SPA) is not a UI at <prefix>/ui.
        (tmp_path / "index.html").write_text("spa", encoding="utf-8")
        app = FastAPI()
        app.include_router(_router(_config()))
        app.mount("/", StaticFiles(directory=str(tmp_path), html=True), name="spa")
        client = TestClient(app)
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.head("/auth/ui/auth.js").status_code == 200
        assert client.get("/auth/ui/config").json()["headless"] is False

    def test_another_app_mounted_at_the_ui_path_does_not_hide_auth_js(self, tmp_path):
        # Only a build_ui_router app owns <prefix>/ui.  A host's own StaticFiles
        # there keeps its files, and the router (included first) still answers
        # auth.js and /config.
        (tmp_path / "logo.svg").write_text("<svg/>", encoding="utf-8")
        app = FastAPI()
        app.include_router(_router(_config()))
        app.mount("/auth/ui", StaticFiles(directory=str(tmp_path)), name="host_assets")
        client = TestClient(app)
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/auth/ui/config").json()["apiPrefix"] == "/auth"
        assert client.get("/auth/ui/logo.svg").text == "<svg/>"


class TestNodeDocument:
    """``/ui/config`` is awesome-node-auth's document, byte for byte with the defaults."""

    def test_reference_document_is_nodes(self):
        assert hashlib.sha256(NODE_DEFAULT_CONFIG).hexdigest() == NODE_CONFIG_SHA256[("/auth", False)]
        assert len(NODE_DEFAULT_CONFIG) == 309

    @pytest.mark.parametrize("headless", [False, True])
    @pytest.mark.parametrize("prefix", ["/auth", "/api/auth"])
    def test_router_only_bytes_are_nodes(self, prefix, headless):
        kwargs = {"ui_config": {"headless": True}} if headless else {}
        client, p = _router_only(prefix, **kwargs)
        body = client.get(f"{p}/ui/config").content
        assert hashlib.sha256(body).hexdigest() == NODE_CONFIG_SHA256[(prefix, headless)], body

    def test_default_bytes(self):
        client, _ = _router_only()
        assert client.get("/auth/ui/config").content == NODE_DEFAULT_CONFIG

    @pytest.mark.parametrize("order", ORDERS)
    @pytest.mark.parametrize("headless", [False, True])
    @pytest.mark.parametrize("prefix", ["/auth", "/api/auth"])
    def test_mounted_ui_bytes_are_nodes(self, order, prefix, headless):
        config = _config(prefix)
        client = _with_ui(order, config, lambda app: mount_ui(app, config, headless=headless))
        body = client.get(f"{prefix}/ui/config").content
        assert hashlib.sha256(body).hexdigest() == NODE_CONFIG_SHA256[(prefix, headless)], body

    def test_key_order(self):
        client, _ = _router_only()
        assert list(client.get("/auth/ui/config").json()) == NODE_CONFIG_ORDER

    @pytest.mark.parametrize("pages", [False, True], ids=["router-only", "with-pages"])
    def test_lang_query_parameter(self, pages):
        config = _config()
        app = FastAPI()
        app.include_router(_router(config))
        if pages:
            mount_ui(app, config)
        client = TestClient(app)
        assert client.get("/auth/ui/config?lang=it").json()["lang"] == "it"
        assert client.get("/auth/ui/config").json()["lang"] == "en"

    def test_lang_defaults_to_the_mailer_language(self):
        mailer = MailerConfig(endpoint="https://mail.example.test", api_key="k", default_lang="de")
        client, p = _router_only(mailer=mailer)
        assert client.get(f"{p}/ui/config").json()["lang"] == "de"
        assert client.get(f"{p}/ui/config?lang=fr").json()["lang"] == "fr"

    def test_ssr_lang_cannot_close_the_script_element(self):
        config = _config()
        app = FastAPI()
        mount_ui(app, config)
        hostile = "</script><script>alert(1)</script>"
        html = TestClient(app).get("/auth/ui/login", params={"lang": hostile}).text
        assert hostile not in html
        assert _ssr_config(html)["lang"] == hostile

    def test_ssr_document_is_nodes(self):
        config = _config()
        app = FastAPI()
        mount_ui(app, config)
        cfg = _ssr_config(TestClient(app).get("/auth/ui/login").text)
        assert json.dumps(cfg, separators=(",", ":")).encode() == NODE_DEFAULT_CONFIG


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
        assert cfg["headless"] is False

    @pytest.mark.parametrize("order", ORDERS)
    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_mounted_pages_report_their_own_headless_switch(self, order, prefix):
        # The router alone would answer headless: true (the configured flag);
        # the mounted UI, which serves the pages, answers false.
        config = _config(prefix, ui_config={"headless": True})
        p = config.api_prefix
        client = _with_ui(order, config, lambda app: mount_ui(app, config))
        assert client.get(f"{p}/ui/config").json()["headless"] is False

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
        # ui_config headless makes the router's answer differ from the mount's.
        config = _config(ui_config={"headless": True})
        client = _with_ui(
            order, config, lambda app: app.mount("/auth/ui", build_ui_router(config=config))
        )
        assert client.get("/auth/ui/login").status_code == 200
        assert client.get("/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/auth/ui/config").json()["headless"] is False

    def test_ui_mounted_under_another_path_leaves_the_router_alone(self):
        # 1.x docstring layout: API under /api/auth, UI by hand at /auth/ui.
        config = _config("/api/auth", ui_config={"headless": True})
        app = FastAPI()
        app.include_router(_router(config))
        app.mount("/auth/ui", build_ui_router(config=config))
        client = TestClient(app)
        assert client.get("/api/auth/ui/auth.js").content == BUNDLED_AUTH_JS
        assert client.get("/api/auth/ui/config").json()["headless"] is True
        assert client.get("/api/auth/ui/login").status_code == 404
        login = client.get("/auth/ui/login")
        assert login.status_code == 200
        mounted = client.get("/auth/ui/config").json()
        assert mounted["headless"] is False
        # Mounted away from <api_prefix>/ui, the UI reports the configured prefix.
        assert mounted["apiPrefix"] == "/api/auth"
        assert _ssr_config(login.text)["apiPrefix"] == "/api/auth"

    @pytest.mark.parametrize("order", ORDERS)
    def test_ui_in_a_sub_application(self, order, tmp_path):
        # Router and mount_ui inside a sub-application mounted at /api: the
        # mount still owns /api/auth/ui (step-aside on the sub-app's own
        # paths), and both documents report the prefix the browser uses.
        assets = _custom_assets(tmp_path, auth_js=b"/* custom runtime */\n")
        config = _config()
        sub = FastAPI()
        if order == "router-first":
            sub.include_router(_router(config))
            mount_ui(sub, config, ui_assets_dir=assets)
        else:
            mount_ui(sub, config, ui_assets_dir=assets)
            sub.include_router(_router(config))
        app = FastAPI()
        app.mount("/api", sub)
        client = TestClient(app)
        assert client.get("/api/auth/ui/auth.js").content == b"/* custom runtime */\n"
        assert client.get("/api/auth/ui/config").json()["apiPrefix"] == "/api/auth"
        login = client.get("/api/auth/ui/login")
        assert "custom login" in login.text
        assert _ssr_config(login.text)["apiPrefix"] == "/api/auth"

    def test_head_auth_js_on_the_mounted_ui(self, tmp_path):
        assets = _custom_assets(tmp_path, auth_js=None)
        config = _config()
        client = _with_ui("router-first", config, lambda app: mount_ui(app, config, ui_assets_dir=assets))
        resp = client.head("/auth/ui/auth.js")
        assert resp.status_code == 200
        assert resp.headers["content-length"] == str(len(BUNDLED_AUTH_JS))

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
