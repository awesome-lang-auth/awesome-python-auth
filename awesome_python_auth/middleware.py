"""CSRF middleware for awesome-python-auth.

Compatible with ng-awesome-node-auth and awesome-node-auth-flutter web mode:

- Sets a ``csrf-token`` cookie (readable by JavaScript) on every response.
- Validates the ``X-CSRF-Token`` request header for non-safe methods
  (POST, PUT, PATCH, DELETE) when the client is using cookie-based auth
  (i.e. **not** the Bearer / ``X-Auth-Strategy: bearer`` strategy).
"""

from __future__ import annotations

import secrets
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from .config import DEFAULT_API_PREFIX

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_CSRF_COOKIE_NAMES = ("__Host-csrf-token", "__Secure-csrf-token", "csrf-token")
_CSRF_HEADER = "x-csrf-token"
_CSRF_COOKIE = "csrf-token"


class CsrfMiddleware(BaseHTTPMiddleware):
    """Starlette/FastAPI middleware that enforces CSRF protection.

    Attach to your FastAPI application **before** including the auth router::

        app.add_middleware(CsrfMiddleware)  # api_prefix defaults to "/auth"

    Parameters
    ----------
    api_prefix:
        The path prefix where the auth router is mounted; keep it equal to
        ``AuthConfig.api_prefix``.  CSRF validation is only enforced for
        requests to this prefix (the prefix itself or a path below it, so
        ``/auth`` does not cover ``/authors``).  Default: ``"/auth"``
        (``"/api/auth"`` until 1.x).
    exclude_paths:
        Additional URL path suffixes to skip CSRF validation on (e.g. refresh,
        login).  Auth-flow endpoints that do not require an active session are
        always excluded automatically.
    cookie_secure:
        Whether to set the ``Secure`` flag on the CSRF cookie.  Defaults to
        ``True`` — override to ``False`` only during local development.
    cookie_same_site:
        ``SameSite`` attribute for the CSRF cookie.  Defaults to ``"lax"``.
    cookie_prefix:
        Optional ``"__Host-"`` or ``"__Secure-"`` prefix for the CSRF cookie name.
    """

    def __init__(
        self,
        app: ASGIApp,
        api_prefix: str = DEFAULT_API_PREFIX,
        exclude_paths: list[str] | None = None,
        cookie_secure: bool = True,
        cookie_same_site: str = "lax",
        cookie_prefix: str | None = None,
    ) -> None:
        super().__init__(app)
        self._prefix = api_prefix.rstrip("/")
        self._cookie_secure = cookie_secure
        self._cookie_same_site = cookie_same_site
        self._csrf_cookie_name = f"{cookie_prefix}{_CSRF_COOKIE}" if cookie_prefix else _CSRF_COOKIE

        # These endpoints do not require an established session.
        base_excluded = {
            "login",
            "register",
            "forgot-password",
            "reset-password",
            "refresh",
            "verify-email",
            "magic-link/verify",
            "sms/verify",
            "2fa/verify",
            "link-verify",
        }
        if exclude_paths:
            base_excluded.update(exclude_paths)
        self._excluded_suffixes = frozenset(base_excluded)

    # ------------------------------------------------------------------

    def _is_under_prefix(self, path: str) -> bool:
        """Return True when *path* is the API prefix or a path below it."""
        if not self._prefix:
            return True
        return path == self._prefix or path.startswith(self._prefix + "/")

    def _is_excluded(self, path: str) -> bool:
        """Return True when CSRF validation should be skipped for *path*."""
        # Strip query string
        clean = path.split("?")[0].rstrip("/")
        for suffix in self._excluded_suffixes:
            if clean.endswith(suffix):
                return True
        return False

    @staticmethod
    def _read_csrf_cookie(request: Request) -> str | None:
        """Read the CSRF token from any of the known cookie names."""
        for name in _CSRF_COOKIE_NAMES:
            value = request.cookies.get(name)
            if value:
                return value
        return None

    @staticmethod
    def _uses_bearer(request: Request) -> bool:
        """Return True when the request uses Bearer-token auth (native mode)."""
        return request.headers.get("x-auth-strategy", "").lower() == "bearer"

    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Only enforce CSRF for requests targeting the auth API
        if self._is_under_prefix(path) and request.method not in _SAFE_METHODS:
            if not self._uses_bearer(request) and not self._is_excluded(path):
                cookie_token = self._read_csrf_cookie(request)
                header_token = request.headers.get(_CSRF_HEADER)
                if not cookie_token or not header_token:
                    return Response(
                        content='{"error":"CSRF token missing"}',
                        status_code=403,
                        media_type="application/json",
                    )
                if not secrets.compare_digest(cookie_token, header_token):
                    return Response(
                        content='{"error":"CSRF token invalid"}',
                        status_code=403,
                        media_type="application/json",
                    )

        response: Response = await call_next(request)

        # Ensure the CSRF cookie is always present
        if self._csrf_cookie_name not in request.cookies:
            token = secrets.token_urlsafe(32)
            response.set_cookie(
                key=self._csrf_cookie_name,
                value=token,
                httponly=False,  # Must be readable by JS
                secure=self._cookie_secure,
                samesite=self._cookie_same_site,
                path="/",
            )

        return response
