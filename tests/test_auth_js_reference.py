"""The bundled auth.js is the awesome-node-auth runtime, byte for byte.

``awesome_python_auth/ui_assets/auth.js`` is vendored from awesome-node-auth
``src/ui/assets/auth.js`` (git blob ``ca41f0a21d59967f526928bbff233242f36726b4``,
last changed in commit ``cc01e99``; the same bytes ship as
``dist/ui-assets/auth.js`` in ``@awesome-lang-auth/node`` 1.10.8).  Until 2.0.0
the copy here had lost its first line (``/**``), so browsers rejected the file
with a syntax error and ``window.AwesomeNodeAuth`` was never defined.

To update the vendored file, copy the new reference over it and change the pin
below in the same commit.  ``.gitattributes`` keeps the file LF on every
checkout, so the hash holds on Windows too.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from awesome_python_auth import AuthConfig, AuthConfigurator, InMemoryUserStore, mount_ui

AUTH_JS_REFERENCE_SHA256 = "ccc707ae777d5625150dca819bd7d1d15ade0db439e7329011d312e231d6698f"
AUTH_JS_REFERENCE_SIZE = 31277

AUTH_JS = Path(__file__).resolve().parent.parent / "awesome_python_auth" / "ui_assets" / "auth.js"


def _served_auth_js(api_prefix: str | None = None) -> bytes:
    config = AuthConfig(access_token_secret="x" * 32)
    if api_prefix is not None:
        config = AuthConfig(access_token_secret="x" * 32, api_prefix=api_prefix)
    app = FastAPI()
    app.include_router(AuthConfigurator(config, InMemoryUserStore()).router())
    path = mount_ui(app, config)
    resp = TestClient(app).get(f"{path}/auth.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    return resp.content


class TestBundledAuthJs:
    def test_file_matches_reference_pin(self):
        data = AUTH_JS.read_bytes()
        assert len(data) == AUTH_JS_REFERENCE_SIZE
        assert hashlib.sha256(data).hexdigest() == AUTH_JS_REFERENCE_SHA256

    def test_file_starts_with_the_doc_comment(self):
        # The line the 1.x copy was missing.
        assert AUTH_JS.read_bytes().startswith(b"/**\n * Universal Authentication Service")

    def test_served_bytes_are_the_reference(self):
        body = _served_auth_js()
        assert hashlib.sha256(body).hexdigest() == AUTH_JS_REFERENCE_SHA256

    def test_served_bytes_are_the_reference_under_a_custom_prefix(self):
        body = _served_auth_js("/api/auth")
        assert hashlib.sha256(body).hexdigest() == AUTH_JS_REFERENCE_SHA256

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_served_file_is_valid_javascript(self, tmp_path):
        script = tmp_path / "auth.js"
        script.write_bytes(_served_auth_js())
        result = subprocess.run(
            ["node", "--check", str(script)], capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, result.stderr
