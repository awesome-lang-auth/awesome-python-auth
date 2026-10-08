"""Tests for bundled auth UI serving and i18n bindings."""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from awesome_python_auth import AuthConfig
from awesome_python_auth.ui_router import mount_ui


def _app() -> FastAPI:
    app = FastAPI()
    mount_ui(app, AuthConfig())  # default prefix: /auth -> /auth/ui
    return app


class TestUiRouter:
    def test_serves_login_page(self):
        client = TestClient(_app())
        resp = client.get("/auth/ui/login")
        assert resp.status_code == 200
        assert 'src="auth.js?v=2"' in resp.text
        assert 'data-i18n="login_title"' in resp.text

    def test_serves_auth_js(self):
        client = TestClient(_app())
        resp = client.get("/auth/ui/auth.js")
        assert resp.status_code == 200
        assert "window.AuthService" in resp.text


class TestUiI18nKeys:
    def test_all_declared_i18n_keys_exist_in_html(self):
        assets_dir = Path(__file__).resolve().parent.parent / "awesome_python_auth" / "ui_assets"
        page_keys = json.loads((assets_dir / "ui-i18n-keys.json").read_text(encoding="utf-8"))

        for page, expected_keys in page_keys.items():
            html = (assets_dir / f"{page}.html").read_text(encoding="utf-8")
            html_keys = set(re.findall(r'data-i18n="([^"]+)"', html))
            missing = [key for key in expected_keys if key not in html_keys]
            assert not missing, f"{page}.html missing i18n keys: {missing}"
