"""Built-in UI router for awesome-python-auth.

Mirrors the ``buildUiRouter`` from awesome-node-auth.

Serves the bundled Vanilla JS authentication pages (login, register,
forgot-password, reset-password, verify-email, magic-link, 2fa) with
Server-Side Rendering (SSR) of the UI configuration, branding colours, and
the ``window.__AUTH_CONFIG__`` bootstrap script.

Everything lives under ``<api_prefix>/ui``, as on every awesome-lang-auth
backend.  The auth router (``AuthConfigurator.router()``) always serves the
runtime script ``<api_prefix>/ui/auth.js`` and ``<api_prefix>/ui/config``, so
with the default prefix ``/auth/ui/auth.js`` answers as soon as the router is
included.  The pages are optional: :func:`mount_ui` mounts them under the same
path (``/auth/ui/login``)::

    from awesome_python_auth import AuthConfigurator, mount_ui

    app.include_router(AuthConfigurator(auth_config, user_store).router())
    mount_ui(app, auth_config)  # pages under <api_prefix>/ui, /auth/ui by default

Or with a custom assets directory::

    mount_ui(app, auth_config, ui_assets_dir="/path/to/custom/ui")

An app mounted at ``<api_prefix>/ui`` (by :func:`mount_ui`, or by hand with
:func:`build_ui_router`) owns that path: it serves its own ``auth.js`` and
``/config``, and the auth router's two routes step aside, whichever was added
first.  ``auth.js`` derives the API prefix from the page URL (everything before
``/ui/``), so the UI has to sit under the prefix of the auth router it talks to.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.routing import Match, Mount
from starlette.types import Scope

from .config import DEFAULT_API_PREFIX

try:  # Starlette >= 0.33: the path routes match against, without root_path.
    from starlette._utils import get_route_path as _get_route_path
except ImportError:  # pragma: no cover - older Starlette than FastAPI 0.115 allows
    def _get_route_path(scope: Scope) -> str:
        return scope["path"]

# Directory bundled with the package
_BUNDLED_ASSETS = Path(__file__).parent / "ui_assets"
# The awesome-node-auth browser runtime, vendored byte for byte.
_BUNDLED_AUTH_JS = _BUNDLED_ASSETS / "auth.js"
_AUTH_JS_MEDIA_TYPE = "text/javascript"


def build_ui_router(
    *,
    config: Any,  # AuthConfig
    api_prefix: str | None = None,
    ui_assets_dir: str | Path | None = None,
    headless: bool = False,
    settings_store: Any = None,  # SettingsStore | None
) -> FastAPI:
    """Build a mini FastAPI application that serves the auth UI.

    Mount it at ``ui_mount_path(api_prefix)`` (or let :func:`mount_ui` do it)
    so ``auth.js`` finds the API from the page URL.  Mounted there, it takes
    over ``<api_prefix>/ui/auth.js`` and ``<api_prefix>/ui/config`` from the
    auth router.

    Parameters
    ----------
    config:
        The :class:`~awesome_python_auth.config.AuthConfig` instance.
    api_prefix:
        Override the API prefix (defaults to ``config.api_prefix``).
    ui_assets_dir:
        Path to a custom directory of HTML/CSS/JS assets.  Defaults to the
        bundled ``ui_assets/`` directory shipped with the package.  If it has
        no ``auth.js``, the bundled one is served.
    headless:
        When ``True``, only the ``/config`` endpoint and static JS/CSS assets
        are served — the HTML pages are not rendered.  Use this when your SPA
        provides its own login UI.
    settings_store:
        Optional :class:`~awesome_python_auth.models.SettingsStore`.  A dict
        stored under the ``"ui_config"`` key replaces ``config.ui_config`` in
        ``/config`` and in the pages, as on the auth router.
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    resolved_api_prefix: str = api_prefix or getattr(config, "api_prefix", DEFAULT_API_PREFIX)
    assets_path = Path(ui_assets_dir) if ui_assets_dir else _BUNDLED_ASSETS

    # ── /config ───────────────────────────────────────────────────────────────

    @app.get("/config")
    async def ui_config(request: Request) -> dict:
        return _build_config(
            config,
            resolved_api_prefix,
            headless=headless,
            ui_cfg=await _stored_ui_config(settings_store),
        )

    # ── /auth.js: the custom one if the assets directory has it ──────────────

    custom_auth_js = assets_path / "auth.js"
    served_auth_js = custom_auth_js if custom_auth_js.is_file() else _BUNDLED_AUTH_JS

    @app.get("/auth.js")
    async def auth_js() -> FileResponse:
        return FileResponse(str(served_auth_js), media_type=_AUTH_JS_MEDIA_TYPE)

    if headless:
        # Headless: only serve static assets (auth.js, base.css)
        _mount_static(app, assets_path)
        return app

    # ── HTML pages with SSR config injection ──────────────────────────────────

    # Set of pages that are valid to serve — avoids path traversal.
    _ALLOWED_PAGES = frozenset(
        p.stem for p in _BUNDLED_ASSETS.glob("*.html")
    ) | frozenset(
        p.stem for p in (assets_path.glob("*.html") if assets_path.exists() else [])
    )
    _ALLOWED_STATIC_EXT = {".js", ".css", ".json", ".map", ".png", ".jpg", ".jpeg", ".svg", ".ico"}
    _ALLOWED_STATIC_FILES = {
        p.name: p
        for p in assets_path.iterdir()
        if p.is_file() and p.suffix.lower() in _ALLOWED_STATIC_EXT
    } if assets_path.exists() else {}

    @app.get("/{page:path}")
    async def serve_page(page: str, request: Request) -> Response:
        raw_path = page.strip("/")
        if "." in raw_path:
            asset_name = raw_path.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[a-zA-Z0-9._-]+", asset_name):
                return Response(status_code=403)
            ext = Path(asset_name).suffix.lower()
            if ext not in _ALLOWED_STATIC_EXT:
                return Response(status_code=404)
            asset_file = _ALLOWED_STATIC_FILES.get(asset_name)
            if asset_file:
                return FileResponse(str(asset_file))
            return Response(status_code=404)

        # Sanitize: strip slashes, keep only the base name, no path separators
        page_name = raw_path.split("/")[-1] or "login"
        # Allow only alphanumeric, hyphens, underscores (no dots or slashes)
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", page_name):
            page_name = "login"

        html_file = assets_path / f"{page_name}.html"
        # Ensure the resolved path stays inside the assets directory
        try:
            html_file.resolve().relative_to(assets_path.resolve())
        except ValueError:
            return Response(status_code=403)

        if not html_file.exists():
            # Fallback to login
            html_file = assets_path / "login.html"
        if not html_file.exists():
            return Response(status_code=404)
        return _render_ssr(
            html_file,
            config,
            resolved_api_prefix,
            ui_cfg=await _stored_ui_config(settings_store),
        )

    _mount_static(app, assets_path)
    return app


def ui_mount_path(api_prefix: str = DEFAULT_API_PREFIX) -> str:
    """Return where the built-in UI is mounted for *api_prefix*: ``<api_prefix>/ui``.

    ``ui_mount_path()`` is ``"/auth/ui"``; ``ui_mount_path("/api/auth")`` is
    ``"/api/auth/ui"``.
    """
    return f"{api_prefix.rstrip('/')}/ui"


def mount_ui(
    app: FastAPI,
    config: Any,  # AuthConfig
    *,
    ui_assets_dir: str | Path | None = None,
    headless: bool = False,
    settings_store: Any = None,  # SettingsStore | None
    name: str = "auth_ui",
) -> str:
    """Mount the built-in UI pages under ``<config.api_prefix>/ui`` and return that path.

    With the default prefix the login page is ``/auth/ui/login``; with
    ``api_prefix="/api/auth"`` it moves to ``/api/auth/ui/login``.  The auth
    router serves ``auth.js`` and ``/config`` there without this call; once
    the UI is mounted it serves them itself (``headless: false`` in
    ``/config``), whether this call comes before or after
    ``app.include_router(configurator.router())``.

    Parameters
    ----------
    app:
        The FastAPI application.
    config:
        The :class:`~awesome_python_auth.config.AuthConfig` instance whose
        ``api_prefix`` the auth router uses.
    ui_assets_dir, headless, settings_store:
        Passed to :func:`build_ui_router`.  Pass the same ``settings_store``
        as to ``router()`` so ``/config`` keeps reading it.
    name:
        Route name of the mount.  Default: ``"auth_ui"``.
    """
    path = ui_mount_path(getattr(config, "api_prefix", DEFAULT_API_PREFIX))
    app.mount(
        path,
        build_ui_router(
            config=config,
            ui_assets_dir=ui_assets_dir,
            headless=headless,
            settings_store=settings_store,
        ),
        name=name,
    )
    return path


# ---------------------------------------------------------------------------
# auth.js and /config on the auth router
# ---------------------------------------------------------------------------


class _UiRuntimeRoute(APIRoute):
    """A route of the auth router under ``<api_prefix>/ui`` that steps aside
    when an app is mounted at that ``/ui`` path.

    The mounted UI (:func:`mount_ui`, or :func:`build_ui_router` mounted by
    hand) then answers the request, so the auth router never shadows it,
    whichever of the two was added to the application first.
    """

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        if match is not Match.NONE and _ui_app_mounted(scope):
            return Match.NONE, {}
        return match, child_scope


def _ui_app_mounted(scope: Scope) -> bool:
    """Whether the application has a mount at the parent path of the request
    (``/auth/ui`` for ``/auth/ui/auth.js``)."""
    ui_path = _get_route_path(scope).rsplit("/", 1)[0]
    routes = getattr(scope.get("app"), "routes", None) or ()
    return any(isinstance(route, Mount) and route.path == ui_path for route in routes)


def _add_runtime_routes(
    router: APIRouter,
    config: Any,  # AuthConfig
    *,
    settings_store: Any = None,  # SettingsStore | None
    on_register: Any = None,
) -> None:
    """Add ``GET /ui/auth.js`` and ``GET /ui/config`` to the auth *router*.

    Called by ``AuthConfigurator.router()``: every awesome-lang-auth backend
    serves the browser runtime at ``<api_prefix>/ui/auth.js`` as soon as its
    auth router is mounted.  Without the pages ``/config`` reports
    ``headless: true``, so ``auth.js`` does not send the browser to a login
    page that is not there (awesome-node-auth's headless mode).
    """
    api_prefix: str = getattr(config, "api_prefix", DEFAULT_API_PREFIX)

    async def ui_auth_js() -> FileResponse:
        return FileResponse(str(_BUNDLED_AUTH_JS), media_type=_AUTH_JS_MEDIA_TYPE)

    async def ui_config() -> dict:
        return _build_config(
            config,
            api_prefix,
            headless=True,
            ui_cfg=await _stored_ui_config(settings_store),
            on_register=on_register,
        )

    router.add_api_route(
        "/ui/auth.js",
        ui_auth_js,
        methods=["GET"],
        include_in_schema=False,
        route_class_override=_UiRuntimeRoute,
    )
    router.add_api_route(
        "/ui/config",
        ui_config,
        methods=["GET"],
        route_class_override=_UiRuntimeRoute,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _stored_ui_config(settings_store: Any) -> dict | None:
    """The ``"ui_config"`` document of *settings_store*, if it holds one."""
    if settings_store is None:
        return None
    stored = await settings_store.get("ui_config")
    return stored if isinstance(stored, dict) and stored else None


def _build_config(
    config: Any,
    api_prefix: str,
    *,
    headless: bool = False,
    ui_cfg: dict | None = None,
    on_register: Any = None,
) -> dict:
    """Build the ``/config`` response payload.

    *ui_cfg* replaces ``config.ui_config`` (a settings-store document);
    *on_register* is the auth router's hook, which enables ``register`` too.
    """
    if ui_cfg is None:
        ui_cfg = getattr(config, "ui_config", None) or {}
    features = {
        "register": bool(
            on_register
            or getattr(config, "on_register", None)
            or ui_cfg.get("features", {}).get("register")
        ),
        "magicLink": bool(
            getattr(config, "on_magic_link_send", None)
            or ui_cfg.get("features", {}).get("magicLink")
        ),
        "sms": bool(getattr(config, "on_sms_send", None) or ui_cfg.get("features", {}).get("sms")),
        "google": bool(ui_cfg.get("features", {}).get("google")),
        "github": bool(ui_cfg.get("features", {}).get("github")),
        "forgotPassword": bool(
            getattr(config, "on_forgot_password", None)
            or ui_cfg.get("features", {}).get("forgotPassword")
        ),
        "verifyEmail": bool(
            getattr(config, "on_send_verification_email", None)
            or ui_cfg.get("features", {}).get("verifyEmail")
        ),
        "twoFactor": bool(ui_cfg.get("features", {}).get("twoFactor")),
    }
    ui_theme = ui_cfg.get("ui", {})
    ui = {
        "primaryColor": ui_theme.get("primaryColor", "#4a90d9"),
        "secondaryColor": ui_theme.get("secondaryColor", "#6c757d"),
        "logoUrl": ui_theme.get("logoUrl"),
        "siteName": ui_theme.get("siteName", "Awesome Auth"),
        "customCss": ui_theme.get("customCss"),
        "bgColor": ui_theme.get("bgColor"),
        "bgImage": ui_theme.get("bgImage"),
        "cardBg": ui_theme.get("cardBg"),
    }
    return {
        "apiPrefix": api_prefix,
        "features": features,
        "ui": ui,
        "headless": headless,
    }


def _render_ssr(
    html_file: Path, config: Any, api_prefix: str, *, ui_cfg: dict | None = None
) -> HTMLResponse:
    """Read an HTML file, inject SSR config, and return the response.

    ``html_file`` must already be validated to be within the assets directory
    by the caller before calling this function.
    """
    # Read from the already-validated, resolved path to avoid any ambiguity
    resolved = html_file.resolve()
    html = resolved.read_text(encoding="utf-8")
    cfg = _build_config(config, api_prefix, ui_cfg=ui_cfg)
    ui_theme = cfg.get("ui", {})

    # Build inline CSS variables (prevents FOUC)
    css_vars = ":root {"
    if ui_theme.get("primaryColor"):
        css_vars += f"--primary-color:{ui_theme['primaryColor']};"
        css_vars += f"--input-focus:{ui_theme['primaryColor']};"
    if ui_theme.get("secondaryColor"):
        css_vars += f"--secondary-color:{ui_theme['secondaryColor']};"
    if ui_theme.get("bgColor"):
        css_vars += f"--bg-color:{ui_theme['bgColor']};"
    if ui_theme.get("cardBg"):
        css_vars += f"--card-bg:{ui_theme['cardBg']};"
    css_vars += "}"
    style_tags = f"<style>{css_vars}</style>"

    if ui_theme.get("customCss"):
        style_tags += f"<style>{ui_theme['customCss']}</style>"

    # Site name + logo substitution
    if ui_theme.get("siteName"):
        safe_name = (
            ui_theme["siteName"]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
        html = re.sub(r"<title>.*?</title>", f"<title>{safe_name}</title>", html, flags=re.DOTALL)
        html = re.sub(
            r'(<h1[^>]*class="site-name"[^>]*>).*?(</h1>)',
            rf"\g<1>{safe_name}\g<2>",
            html,
            flags=re.DOTALL,
        )

    if ui_theme.get("logoUrl"):
        html = html.replace(
            '<img src="" alt="Logo" class="logo hidden">',
            f'<img src="{ui_theme["logoUrl"]}" alt="Logo" class="logo">',
        )

    # Bootstrap config for auth.js
    script_tag = f"<script>window.__AUTH_CONFIG__ = {json.dumps(cfg)};</script>"
    html = html.replace("</head>", f"{style_tags}\n{script_tag}\n</head>")

    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Content-Type": "text/html; charset=utf-8",
        },
    )


def _mount_static(app: FastAPI, assets_path: Path) -> None:
    """Mount the static file directory on the root of the app."""
    if assets_path.exists():
        app.mount(
            "/",
            StaticFiles(directory=str(assets_path), html=False),
            name="ui_static",
        )
