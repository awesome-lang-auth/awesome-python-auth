"""Auth router factory for awesome-python-auth.

Creates a FastAPI APIRouter that exposes all endpoints expected by
ng-awesome-node-auth (Angular) and awesome-node-auth-flutter (Dart/Flutter).

Endpoint list
-------------
GET  /me
POST /login
POST /register
POST /logout
POST /refresh
PATCH /profile
DELETE /account

POST /forgot-password
POST /reset-password
POST /change-password
POST /send-verification-email
GET  /verify-email

POST /change-email/request
POST /change-email/confirm

POST /magic-link/send
POST /magic-link/verify

POST /sms/send
POST /sms/verify
POST /add-phone

POST /2fa/setup
POST /2fa/verify-setup
POST /2fa/verify
POST /2fa/disable

GET  /sessions
DELETE /sessions/{handle}

GET  /linked-accounts
POST /link-request
POST /link-verify
DELETE /linked-accounts/{provider}/{provider_account_id}
GET  /oauth/{provider}
GET  /oauth/{provider}/callback

GET  /ui/config
GET  /tools/stream (SSE)
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse

from .dependencies import (
    _register_cookie_names,
    _register_secret,
    _register_session_check,
    get_current_user,
    require_auth,
)
from .events import AuthEventNames
from .jwt_utils import (
    create_access_token,
    create_refresh_token,
    create_temp_token,
    decode_token,
    generate_opaque_token,
)
from .models import (
    AddPhoneBody,
    AuthUser,
    ChangePasswordBody,
    ConfirmEmailChangeBody,
    LinkRequestBody,
    LinkVerifyBody,
    LoginBody,
    MagicLinkSendBody,
    MagicLinkVerifyBody,
    RefreshBody,
    RegisterBody,
    RequestEmailChangeBody,
    ResetPasswordBody,
    SessionInfo,
    SettingsStore,
    SmsSendBody,
    SmsVerifyBody,
    StoredSession,
    StoredUser,
    TotpSetupData,
    UpdateProfileBody,
    UserStore,
    Validate2faBody,
    ValidateSmsBody,
    Verify2faSetupBody,
)
from .password_utils import hash_password, verify_password

# ── Cookie / header names ────────────────────────────────────────────────────
_BASE_ACCESS_TOKEN_COOKIE = "access-token"
_BASE_REFRESH_TOKEN_COOKIE = "refresh-token"

# ── Defaults ─────────────────────────────────────────────────────────────────
_DEFAULT_ACCESS_EXPIRES = 900  # 15 minutes
_DEFAULT_REFRESH_EXPIRES = 604800  # 7 days


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    *,
    secure: bool,
    same_site: str,
    access_expires: int,
    refresh_expires: int,
    domain: str | None,
    access_cookie_name: str,
    refresh_cookie_name: str,
) -> None:
    """Attach the access-token and refresh-token HttpOnly cookies to *response*."""
    kw: dict[str, Any] = {"httponly": True, "secure": secure, "path": "/"}
    if domain:
        kw["domain"] = domain

    response.set_cookie(
        key=access_cookie_name,
        value=access_token,
        max_age=access_expires,
        samesite=same_site,
        **kw,
    )
    response.set_cookie(
        key=refresh_cookie_name,
        value=refresh_token,
        max_age=refresh_expires,
        samesite=same_site,
        **kw,
    )


def _clear_auth_cookies(
    response: Response,
    *,
    secure: bool,
    domain: str | None,
    access_cookie_names: tuple[str, ...],
    refresh_cookie_names: tuple[str, ...],
) -> None:
    kw: dict[str, Any] = {"httponly": True, "secure": secure, "path": "/"}
    if domain:
        kw["domain"] = domain
    for cookie_name in access_cookie_names:
        response.delete_cookie(cookie_name, **kw)
    for cookie_name in refresh_cookie_names:
        response.delete_cookie(cookie_name, **kw)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _cookie_name_with_prefix(base_name: str, prefix: str | None) -> str:
    if not prefix:
        return base_name
    return f"{prefix}{base_name}"


def _read_cookie(request: Request, names: tuple[str, ...]) -> str | None:
    for name in names:
        value = request.cookies.get(name)
        if value:
            return value
    return None


async def _resolve_hook_result(hook: Any, *args: Any) -> Any:
    value = hook(*args)
    if hasattr(value, "__await__"):
        return await value
    return value


logger = logging.getLogger(__name__)

_CORRELATION_ID_PATTERN = re.compile(r"^[\w.:-]{1,128}$")
_MAX_EVENT_EMAIL_LENGTH = 320


def _request_event_context(request: Request | None) -> dict[str, Any]:
    if request is None:
        return {}
    corr_header = request.headers.get("x-correlation-id")
    correlation_id = (
        corr_header
        if corr_header and _CORRELATION_ID_PATTERN.match(corr_header)
        else None
    )
    return {
        "ip": request.client.host if request.client else None,
        "userAgent": request.headers.get("user-agent"),
        "correlationId": correlation_id,
    }


def _event_email(value: Any) -> str | None:
    if isinstance(value, str):
        return value[:_MAX_EVENT_EMAIL_LENGTH]
    return None


def _oauth_conflict_data(provider: str, err_data: Any) -> dict[str, Any]:
    if not isinstance(err_data, dict):
        return {"provider": provider}
    data: dict[str, Any] = {"provider": provider}
    email = _event_email(err_data.get("email"))
    if email:
        data["email"] = email
    acct_id = err_data.get("providerAccountId") or err_data.get("provider_account_id")
    if isinstance(acct_id, str):
        data["providerAccountId"] = acct_id
    return data


class AuthConfigurator:
    """Entry point for configuring the auth system.

    Parameters
    ----------
    config:
        An :class:`~awesome_python_auth.config.AuthConfig` instance.
    user_store:
        An :class:`~awesome_python_auth.models.UserStore` implementation.
    """

    def __init__(self, config: "AuthConfig", user_store: UserStore) -> None:  # noqa: F821
        self._config = config
        self._store = user_store
        # Register secret globally so the dependency helpers can find it.
        _register_secret(config.access_token_secret)
        # Register resource server config if provided
        rs_cfg = getattr(config, "resource_server", None)
        if rs_cfg is not None and getattr(rs_cfg, "enabled", False):
            from .dependencies import _register_resource_server
            _register_resource_server(rs_cfg)

    # ------------------------------------------------------------------
    # Router factory
    # ------------------------------------------------------------------

    def router(
        self,
        *,
        settings_store: SettingsStore | None = None,
        on_register: Any = None,
        event_bus: Any = None,
    ) -> APIRouter:
        """Return a configured :class:`fastapi.APIRouter`.

        Every route sits under ``AuthConfig.api_prefix`` (default ``"/auth"``).
        The built-in UI is mounted separately, after this router is included,
        with :func:`~awesome_python_auth.ui_router.mount_ui`.

        Parameters
        ----------
        settings_store:
            Optional settings store for UI configuration.
        on_register:
            Optional async callable ``(data: StoredUser) -> StoredUser`` called
            just before a new user is persisted.  Use it to add custom logic
            (e.g. role assignment, email sending).
        event_bus:
            Optional :class:`~awesome_python_auth.events.AuthEventBus` instance
            for auto-publishing authentication and lifecycle events.
        """
        cfg = self._config
        store = self._store

        effective_event_bus = (
            event_bus
            if event_bus is not None
            else (
                getattr(cfg, "event_bus", None)
                or (
                    getattr(cfg.tools, "event_bus", None)
                    if getattr(cfg, "tools", None)
                    else None
                )
            )
        )

        def _emit(
            event_name: str,
            payload: dict[str, Any],
            req: Request | None = None,
        ) -> None:
            if effective_event_bus is None:
                return
            ctx = _request_event_context(req)
            merged = {**ctx, **payload}
            clean = {k: v for k, v in merged.items() if v is not None}
            if "data" in clean and isinstance(clean["data"], dict):
                clean["data"] = {k: v for k, v in clean["data"].items() if v is not None}
            try:
                effective_event_bus.publish(event_name, clean)
            except Exception:
                logger.exception("AuthEventBus: error publishing %s", event_name)

        router = APIRouter(prefix=cfg.api_prefix)

        # Shortcuts
        secret = cfg.access_token_secret
        secure = cfg.cookie_secure
        same_site = cfg.cookie_same_site
        domain = cfg.cookie_domain
        access_exp = cfg.access_token_expires_in
        refresh_exp = cfg.refresh_token_expires_in
        cookie_prefix = cfg.cookie_prefix
        access_cookie_name = _cookie_name_with_prefix(_BASE_ACCESS_TOKEN_COOKIE, cookie_prefix)
        refresh_cookie_name = _cookie_name_with_prefix(_BASE_REFRESH_TOKEN_COOKIE, cookie_prefix)
        access_cookie_names = (
            access_cookie_name,
            _BASE_ACCESS_TOKEN_COOKIE,
            "__Host-access-token",
            "__Secure-access-token",
        )
        refresh_cookie_names = (
            refresh_cookie_name,
            _BASE_REFRESH_TOKEN_COOKIE,
            "__Host-refresh-token",
            "__Secure-refresh-token",
        )
        _register_cookie_names(access_cookie_names)
        session_check_on = (cfg.session_check_on or "none").lower().strip()
        if session_check_on not in {"allcalls", "refresh", "none"}:
            raise ValueError(
                f"AuthConfig.session_check_on must be one of: allcalls, refresh, none "
                f"(got: {session_check_on!r})"
            )
        _register_session_check(session_check_on, store)

        def _jwt_payload_with_session(user: AuthUser, session_handle: str) -> dict[str, Any]:
            return {**user.to_jwt_payload(), "sessionHandle": session_handle}

        # ── IdP mode setup ────────────────────────────────────────────────────
        _idp_cfg = getattr(cfg, "id_provider", None)
        _idp_active = _idp_cfg is not None and (
            getattr(_idp_cfg, "enabled", False) or getattr(_idp_cfg, "private_key", None)
        )
        if _idp_active:
            from .idp import resolve_idp_keypair
            _idp_private_key, _idp_public_key = resolve_idp_keypair(_idp_cfg)
        else:
            _idp_private_key = _idp_public_key = None

        def _make_tokens(user: StoredUser, session_handle: str) -> tuple[str, str]:
            if _idp_active and _idp_private_key:
                from .jwt_utils import create_idp_access_token, create_idp_refresh_token
                payload = _jwt_payload_with_session(user.to_auth_user(), session_handle)
                access = create_idp_access_token(
                    payload, _idp_private_key,
                    expires_in_seconds=_idp_cfg.token_expiry,
                    issuer=getattr(_idp_cfg, "issuer", None),
                )
                refresh = create_idp_refresh_token(
                    payload, _idp_private_key,
                    expires_in_seconds=_idp_cfg.refresh_token_expiry,
                    issuer=getattr(_idp_cfg, "issuer", None),
                )
                return access, refresh
            access = create_access_token(
                _jwt_payload_with_session(user.to_auth_user(), session_handle),
                secret,
                access_exp,
            )
            refresh = create_refresh_token(user.id, session_handle, secret, refresh_exp)
            return access, refresh

        async def _make_tokens_enriched(user: StoredUser, session_handle: str) -> tuple[str, str]:
            """Like _make_tokens but enriches roles/permissions from the RBAC store if configured."""
            auth_user = user.to_auth_user()
            rbac = cfg.roles_permissions_store
            if rbac is not None:
                roles = await rbac.get_roles_for_user(user.id, user.tenant_id)
                perms = await rbac.get_permissions_for_user(user.id, user.tenant_id)
                # Merge store roles with any roles already on the user record
                merged_roles = list(dict.fromkeys((auth_user.roles or []) + roles))
                merged_perms = list(dict.fromkeys((auth_user.permissions or []) + perms))
                auth_user = auth_user.model_copy(update={"roles": merged_roles or None, "permissions": merged_perms or None})
            if _idp_active and _idp_private_key:
                from .jwt_utils import create_idp_access_token, create_idp_refresh_token
                payload = _jwt_payload_with_session(auth_user, session_handle)
                access = create_idp_access_token(
                    payload, _idp_private_key,
                    expires_in_seconds=_idp_cfg.token_expiry,
                    issuer=getattr(_idp_cfg, "issuer", None),
                )
                refresh = create_idp_refresh_token(
                    payload, _idp_private_key,
                    expires_in_seconds=_idp_cfg.refresh_token_expiry,
                    issuer=getattr(_idp_cfg, "issuer", None),
                )
                return access, refresh
            access = create_access_token(_jwt_payload_with_session(auth_user, session_handle), secret, access_exp)
            refresh = create_refresh_token(user.id, session_handle, secret, refresh_exp)
            return access, refresh

        async def _create_session(
            user: StoredUser, request: Request
        ) -> tuple[str, str, StoredSession]:
            session = StoredSession(
                user_id=user.id,
                refresh_token_hash="",  # filled below
                user_agent=request.headers.get("user-agent"),
                ip_address=request.client.host if request.client else None,
            )
            access_token, refresh_token = await _make_tokens_enriched(user, session.handle)
            session.refresh_token_hash = _hash_token(refresh_token)
            await store.create_session(session)
            return access_token, refresh_token, session

        def _is_bearer(request: Request) -> bool:
            return request.headers.get("x-auth-strategy", "").lower() == "bearer"

        def _send_tokens(
            request: Request,
            response: Response,
            access_token: str,
            refresh_token: str,
            user: StoredUser,
        ) -> dict[str, Any]:
            """Set cookies (web) or return tokens in body (native)."""
            auth_user = user.to_auth_user()
            if _is_bearer(request):
                return {
                    "success": True,
                    "accessToken": access_token,
                    "refreshToken": refresh_token,
                    **auth_user.to_api_dict(),
                }
            _set_auth_cookies(
                response,
                access_token,
                refresh_token,
                secure=secure,
                same_site=same_site,
                access_expires=access_exp,
                refresh_expires=refresh_exp,
                domain=domain,
                access_cookie_name=access_cookie_name,
                refresh_cookie_name=refresh_cookie_name,
            )
            return {"success": True, **auth_user.to_api_dict()}

        # ── /me ─────────────────────────────────────────────────────────────

        @router.get("/me")
        async def me(
            user: AuthUser | None = Depends(get_current_user),
        ) -> dict:
            if user is None:
                raise HTTPException(status_code=401, detail="Not authenticated")
            return user.to_api_dict()

        # ── /login ───────────────────────────────────────────────────────────

        @router.post("/login")
        async def login(body: LoginBody, request: Request, response: Response) -> dict:
            stored = await store.get_by_email(body.email)
            if not stored or not verify_password(body.password, stored.hashed_password or ""):
                fail_data: dict[str, Any] = {"method": "password"}
                email_clean = _event_email(body.email)
                if email_clean:
                    fail_data["email"] = email_clean
                _emit(AuthEventNames.AUTH_LOGIN_FAILED, {"data": fail_data}, request)
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # 2FA required?
            if stored.is_totp_enabled:
                temp = create_temp_token(stored.id, secret)
                return {
                    "success": True,
                    "requiresTwoFactor": True,
                    "tempToken": temp,
                    "requires2FASetup": False,
                    "available2faMethods": ["totp"],
                }

            access_token, refresh_token, session = await _create_session(stored, request)
            stored.last_login = datetime.now(timezone.utc)
            await store.update(stored)
            _emit(
                AuthEventNames.AUTH_LOGIN_SUCCESS,
                {
                    "userId": stored.id,
                    "tenantId": getattr(stored, "tenant_id", None),
                    "sessionId": session.handle if session else None,
                    "data": {"method": "password"},
                },
                request,
            )
            return _send_tokens(request, response, access_token, refresh_token, stored)

        # ── /register ────────────────────────────────────────────────────────

        @router.post("/register", status_code=201)
        async def register(body: RegisterBody, request: Request) -> dict:
            existing = await store.get_by_email(body.email)
            if existing:
                raise HTTPException(status_code=409, detail="Email already registered")

            new_user = StoredUser(
                email=body.email.lower().strip(),
                hashed_password=hash_password(body.password),
                first_name=body.first_name,
                last_name=body.last_name,
                name=f"{body.first_name} {body.last_name}".strip() or None,
            )

            if on_register:
                new_user = await on_register(new_user)
            else:
                await store.create(new_user)

            if cfg.email and cfg.email.get("enabled", False):
                # Placeholder: send verification email
                pass

            _emit(
                AuthEventNames.USER_CREATED,
                {
                    "userId": new_user.id,
                    "tenantId": getattr(new_user, "tenant_id", None),
                    "data": {
                        "email": _event_email(new_user.email),
                        "method": "custom" if on_register else "default",
                    },
                },
                request,
            )

            return {"success": True, "userId": new_user.id}

        # ── /logout ──────────────────────────────────────────────────────────

        @router.post("/logout")
        async def logout(request: Request, response: Response) -> dict:
            user_id: str | None = None
            handle: str | None = None
            refresh_cookie = _read_cookie(request, refresh_cookie_names)
            if refresh_cookie:
                try:
                    payload = decode_token(refresh_cookie, secret)
                    handle = payload.get("sessionHandle")
                    user_id = payload.get("sub")
                    if handle:
                        await store.delete_session(handle)
                except Exception:
                    pass
            if not user_id:
                access_cookie = _read_cookie(request, access_cookie_names)
                if access_cookie:
                    try:
                        p = decode_token(access_cookie, secret)
                        user_id = p.get("sub")
                        if not handle:
                            handle = p.get("sessionHandle")
                    except Exception:
                        pass
            if not user_id:
                auth_header = request.headers.get("authorization", "")
                if auth_header.lower().startswith("bearer "):
                    token = auth_header[7:].strip()
                    try:
                        p = decode_token(token, secret)
                        user_id = p.get("sub")
                        if not handle:
                            handle = p.get("sessionHandle")
                    except Exception:
                        pass
            _clear_auth_cookies(
                response,
                secure=secure,
                domain=domain,
                access_cookie_names=access_cookie_names,
                refresh_cookie_names=refresh_cookie_names,
            )
            _emit(
                AuthEventNames.AUTH_LOGOUT,
                {
                    "userId": user_id,
                    "sessionId": handle,
                },
                request,
            )
            return {"success": True}

        # ── /refresh ─────────────────────────────────────────────────────────

        @router.post("/refresh")
        async def refresh_token(
            body: RefreshBody | None = None,
            request: Request = None,  # type: ignore[assignment]
            response: Response = None,  # type: ignore[assignment]
        ) -> dict:
            # Native clients send refreshToken in the body;
            # web clients send it via the HttpOnly cookie.
            raw_refresh: str | None = None
            if body and body.refresh_token:
                raw_refresh = body.refresh_token
            if not raw_refresh:
                raw_refresh = _read_cookie(request, refresh_cookie_names)

            if not raw_refresh:
                raise HTTPException(status_code=401, detail="No refresh token provided")

            try:
                payload = decode_token(raw_refresh, secret)
            except Exception:
                raise HTTPException(status_code=401, detail="Invalid refresh token")

            user_id = payload.get("sub")
            session_handle = payload.get("sessionHandle")

            stored_session = await store.get_session_by_handle(session_handle) if session_handle else None
            is_session_invalid = not stored_session or not user_id or stored_session.user_id != user_id
            if session_check_on in {"refresh", "allcalls"} and is_session_invalid:
                return JSONResponse(
                    content={"success": False, "code": "SESSION_REVOKED", "message": "Session revoked"},
                    status_code=401,
                )
            if stored_session:
                token_hash = _hash_token(raw_refresh)
                if stored_session.refresh_token_hash != token_hash:
                    return JSONResponse(
                        content={"success": False, "code": "SESSION_REVOKED", "message": "Session revoked"},
                        status_code=401,
                    )

            stored_user = await store.get_by_id(user_id) if user_id else None
            if not stored_user:
                raise HTTPException(status_code=401, detail="User not found")

            access_token, new_refresh = await _make_tokens_enriched(stored_user, session_handle or "")
            if stored_session:
                stored_session.refresh_token_hash = _hash_token(new_refresh)
                stored_session.last_active_at = datetime.now(timezone.utc)
                await store.update_session(stored_session)

            _emit(
                AuthEventNames.SESSION_ROTATED,
                {
                    "userId": stored_user.id,
                    "tenantId": getattr(stored_user, "tenant_id", None),
                    "sessionId": session_handle,
                    "data": {"previousSessionId": session_handle},
                },
                request,
            )

            if _is_bearer(request):
                return {"success": True, "accessToken": access_token, "refreshToken": new_refresh}

            _set_auth_cookies(
                response,
                access_token,
                new_refresh,
                secure=secure,
                same_site=same_site,
                access_expires=access_exp,
                refresh_expires=refresh_exp,
                domain=domain,
                access_cookie_name=access_cookie_name,
                refresh_cookie_name=refresh_cookie_name,
            )
            return {"success": True}

        # ── /profile ─────────────────────────────────────────────────────────

        @router.patch("/profile")
        async def update_profile(
            body: UpdateProfileBody,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            stored.first_name = body.first_name
            stored.last_name = body.last_name
            stored.name = f"{body.first_name} {body.last_name}".strip() or None
            await store.update(stored)
            return {"success": True}

        # ── /account ─────────────────────────────────────────────────────────

        @router.delete("/account")
        async def delete_account(
            user: AuthUser = Depends(require_auth),
            request: Request = None,  # type: ignore[assignment]
            response: Response = None,  # type: ignore[assignment]
        ) -> dict:
            await store.delete_sessions_for_user(user.sub)
            await store.delete(user.sub)
            _clear_auth_cookies(
                response,
                secure=secure,
                domain=domain,
                access_cookie_names=access_cookie_names,
                refresh_cookie_names=refresh_cookie_names,
            )
            _emit(
                AuthEventNames.USER_DELETED,
                {
                    "userId": user.sub,
                    "tenantId": getattr(user, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        # ── /forgot-password ─────────────────────────────────────────────────

        @router.post("/forgot-password")
        async def forgot_password(body: dict) -> dict:
            email = body.get("email", "")
            stored = await store.get_by_email(email)
            if stored:
                token = generate_opaque_token()
                stored.reset_password_token = _hash_token(token)
                await store.update(stored)
                # cfg.email handler can send the email; not implemented here
                if cfg.on_forgot_password:
                    await cfg.on_forgot_password(stored, token)
            # Always return success to avoid email enumeration
            return {"success": True}

        # ── /reset-password ──────────────────────────────────────────────────

        @router.post("/reset-password")
        async def reset_password(body: ResetPasswordBody, request: Request) -> dict:
            hashed = _hash_token(body.token)
            found = await store.find_by_reset_token(hashed)
            if not found:
                raise HTTPException(status_code=400, detail="Invalid or expired token")
            found.hashed_password = hash_password(body.password)
            found.reset_password_token = None
            await store.update(found)
            _emit(
                AuthEventNames.USER_PASSWORD_CHANGED,
                {
                    "userId": found.id,
                    "tenantId": getattr(found, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        # ── /change-password ─────────────────────────────────────────────────

        @router.post("/change-password")
        async def change_password(
            body: ChangePasswordBody,
            request: Request,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            if body.current_password and not verify_password(
                body.current_password, stored.hashed_password or ""
            ):
                raise HTTPException(status_code=400, detail="Current password is incorrect")
            stored.hashed_password = hash_password(body.new_password)
            await store.update(stored)
            _emit(
                AuthEventNames.USER_PASSWORD_CHANGED,
                {
                    "userId": user.sub,
                    "tenantId": getattr(user, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        # ── /send-verification-email ─────────────────────────────────────────

        @router.post("/send-verification-email")
        async def send_verification_email(
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            if stored.is_email_verified:
                return {"success": True, "message": "Email already verified"}
            token = generate_opaque_token()
            stored.verification_token = _hash_token(token)
            await store.update(stored)
            if cfg.on_send_verification_email:
                await cfg.on_send_verification_email(stored, token)
            return {"success": True}

        # ── /verify-email ────────────────────────────────────────────────────

        @router.get("/verify-email")
        async def verify_email(token: str, request: Request) -> dict:
            hashed = _hash_token(token)
            found = await store.find_by_verification_token(hashed)
            if not found:
                raise HTTPException(status_code=400, detail="Invalid or expired token")
            found.is_email_verified = True
            found.verification_token = None
            await store.update(found)
            _emit(
                AuthEventNames.USER_EMAIL_VERIFIED,
                {
                    "userId": found.id,
                    "tenantId": getattr(found, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        # ── /change-email/* ──────────────────────────────────────────────────

        @router.post("/change-email/request")
        async def request_email_change(
            body: RequestEmailChangeBody,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            conflict = await store.get_by_email(body.new_email)
            if conflict:
                raise HTTPException(status_code=409, detail="Email already in use")
            token = generate_opaque_token()
            stored.pending_email = body.new_email
            stored.pending_email_token = _hash_token(token)
            await store.update(stored)
            if cfg.on_request_email_change:
                await cfg.on_request_email_change(stored, body.new_email, token)
            return {"success": True}

        @router.post("/change-email/confirm")
        async def confirm_email_change(
            body: ConfirmEmailChangeBody,
            request: Request,
            response: Response,
        ) -> dict:
            hashed = _hash_token(body.token)
            found = await store.find_by_pending_email_token(hashed)
            if not found:
                raise HTTPException(status_code=400, detail="Invalid or expired token")
            old_email = found.email
            new_email = found.pending_email or found.email
            found.email = new_email
            found.pending_email = None
            found.pending_email_token = None
            await store.update(found)
            # Reissue tokens with updated email
            access_token, refresh_token, session = await _create_session(found, request)
            _emit(
                AuthEventNames.USER_EMAIL_CHANGED,
                {
                    "userId": found.id,
                    "tenantId": getattr(found, "tenant_id", None),
                    "data": {
                        "oldEmail": _event_email(old_email),
                        "newEmail": _event_email(new_email),
                    },
                },
                request,
            )
            if _is_bearer(request):
                return {"success": True, "accessToken": access_token, "refreshToken": refresh_token}
            _set_auth_cookies(
                response, access_token, refresh_token,
                secure=secure, same_site=same_site,
                access_expires=access_exp, refresh_expires=refresh_exp,
                domain=domain,
                access_cookie_name=access_cookie_name,
                refresh_cookie_name=refresh_cookie_name,
            )
            return {"success": True}

        # ── /magic-link/* ────────────────────────────────────────────────────

        @router.post("/magic-link/send")
        async def magic_link_send(body: MagicLinkSendBody) -> dict:
            if cfg.on_magic_link_send:
                await cfg.on_magic_link_send(body.email, body.temp_token, body.mode)
            else:
                # Default no-op — wire up cfg.on_magic_link_send to send emails
                pass
            return {"success": True}

        @router.post("/magic-link/verify")
        async def magic_link_verify(
            body: MagicLinkVerifyBody, request: Request, response: Response
        ) -> dict:
            if cfg.on_magic_link_verify:
                result = await cfg.on_magic_link_verify(body.token, body.mode)
                if result:
                    stored = await store.get_by_id(result)
                    if stored:
                        access_token, refresh_token, session = await _create_session(stored, request)
                        _emit(
                            AuthEventNames.AUTH_LOGIN_SUCCESS,
                            {
                                "userId": stored.id,
                                "tenantId": getattr(stored, "tenant_id", None),
                                "sessionId": session.handle if session else None,
                                "data": {"method": "magic-link"},
                            },
                            request,
                        )
                        return _send_tokens(request, response, access_token, refresh_token, stored)
            raise HTTPException(status_code=400, detail="Invalid or expired magic link")

        # ── /sms/* ───────────────────────────────────────────────────────────

        @router.post("/sms/send")
        async def sms_send(body: SmsSendBody) -> dict:
            if cfg.on_sms_send:
                await cfg.on_sms_send(body.email, body.temp_token, body.mode)
            return {"success": True}

        @router.post("/sms/verify")
        async def sms_verify(
            body: SmsVerifyBody, request: Request, response: Response
        ) -> dict:
            if cfg.on_sms_verify:
                result = await cfg.on_sms_verify(
                    body.user_id, body.temp_token, body.code, body.mode
                )
                if result:
                    stored = await store.get_by_id(result)
                    if stored:
                        access_token, refresh_token, session = await _create_session(stored, request)
                        _emit(
                            AuthEventNames.AUTH_LOGIN_SUCCESS,
                            {
                                "userId": stored.id,
                                "tenantId": getattr(stored, "tenant_id", None),
                                "sessionId": session.handle if session else None,
                                "data": {"method": "sms"},
                            },
                            request,
                        )
                        return _send_tokens(request, response, access_token, refresh_token, stored)
            raise HTTPException(status_code=400, detail="Invalid SMS code")

        @router.post("/add-phone")
        async def add_phone(
            body: AddPhoneBody,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            stored.phone_number = body.phone_number
            await store.update(stored)
            return {"success": True}

        # ── /2fa/* ───────────────────────────────────────────────────────────

        @router.post("/2fa/setup")
        async def setup_2fa(
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            issuer = cfg.totp_issuer or "awesome-python-auth"
            provisioning_uri = totp.provisioning_uri(name=stored.email, issuer_name=issuer)
            try:
                import qrcode
                import io
                import base64
                qr = qrcode.make(provisioning_uri)
                buf = io.BytesIO()
                qr.save(buf, format="PNG")
                qr_code = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
            except ImportError:
                qr_code = f"data:text/plain;base64,{provisioning_uri}"
            return {"secret": totp_secret, "qrCode": qr_code}

        @router.post("/2fa/verify-setup")
        async def verify_2fa_setup(
            body: Verify2faSetupBody,
            request: Request,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            totp = pyotp.TOTP(body.secret)
            if not totp.verify(body.token, valid_window=1):
                raise HTTPException(status_code=400, detail="Invalid TOTP code")
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            stored.is_totp_enabled = True
            stored.totp_secret = body.secret
            await store.update(stored)
            _emit(
                AuthEventNames.USER_2FA_ENABLED,
                {
                    "userId": user.sub,
                    "tenantId": getattr(user, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        @router.post("/2fa/verify")
        async def verify_2fa(
            body: Validate2faBody, request: Request, response: Response
        ) -> dict:
            try:
                payload = decode_token(body.temp_token, secret)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid temp token")
            if payload.get("purpose") != "2fa":
                raise HTTPException(status_code=400, detail="Invalid token purpose")
            user_id = payload.get("sub")
            stored = await store.get_by_id(user_id) if user_id else None
            if not stored or not stored.totp_secret:
                raise HTTPException(status_code=400, detail="2FA not configured")
            totp = pyotp.TOTP(stored.totp_secret)
            if not totp.verify(body.totp_code, valid_window=1):
                raise HTTPException(status_code=400, detail="Invalid TOTP code")
            access_token, refresh_token, session = await _create_session(stored, request)
            _emit(
                AuthEventNames.AUTH_LOGIN_SUCCESS,
                {
                    "userId": stored.id,
                    "tenantId": getattr(stored, "tenant_id", None),
                    "sessionId": session.handle if session else None,
                    "data": {"method": "totp"},
                },
                request,
            )
            return _send_tokens(request, response, access_token, refresh_token, stored)

        @router.post("/2fa/disable")
        async def disable_2fa(
            request: Request,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            stored.is_totp_enabled = False
            stored.totp_secret = None
            await store.update(stored)
            _emit(
                AuthEventNames.USER_2FA_DISABLED,
                {
                    "userId": user.sub,
                    "tenantId": getattr(user, "tenant_id", None),
                },
                request,
            )
            return {"success": True}

        # ── /sessions/* ──────────────────────────────────────────────────────

        @router.get("/sessions")
        async def get_sessions(
            user: AuthUser = Depends(require_auth),
            request: Request = None,  # type: ignore[assignment]
        ) -> dict:
            sessions = await store.get_sessions_for_user(user.sub)
            refresh_cookie = _read_cookie(request, refresh_cookie_names) if request else None
            current_handle: str | None = None
            if refresh_cookie:
                try:
                    p = decode_token(refresh_cookie, secret)
                    current_handle = p.get("sessionHandle")
                except Exception:
                    pass
            return {
                "sessions": [
                    SessionInfo(
                        handle=s.handle,
                        user_id=s.user_id,
                        user_agent=s.user_agent,
                        ip_address=s.ip_address,
                        created_at=s.created_at,
                        last_active_at=s.last_active_at,
                        is_current=(s.handle == current_handle),
                    ).to_api_dict()
                    for s in sessions
                ]
            }

        @router.delete("/sessions/{handle}")
        async def revoke_session(
            handle: str,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            session = await store.get_session_by_handle(handle)
            if not session or session.user_id != user.sub:
                raise HTTPException(status_code=404, detail="Session not found")
            await store.delete_session(handle)
            return {"success": True}

        # ── /linked-accounts/* ───────────────────────────────────────────────

        @router.get("/linked-accounts")
        async def get_linked_accounts(
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            # Linked accounts are stored in metadata by convention.
            stored = await store.get_by_id(user.sub)
            accounts = (stored.metadata or {}).get("linkedAccounts", []) if stored else []
            return {"linkedAccounts": accounts}

        @router.post("/link-request")
        async def link_request(
            body: LinkRequestBody,
            user: AuthUser | None = Depends(get_current_user),
        ) -> dict:
            if cfg.on_link_request:
                await cfg.on_link_request(body.email, body.provider, user)
            return {"success": True}

        @router.post("/link-verify")
        async def link_verify(
            body: LinkVerifyBody,
            request: Request,
            response: Response,
        ) -> dict:
            if cfg.on_link_verify:
                user_id = await cfg.on_link_verify(body.token, body.provider, body.login_after_linking)
                if user_id and body.login_after_linking:
                    stored = await store.get_by_id(user_id)
                    if stored:
                        access_token, refresh_token, _ = await _create_session(stored, request)
                        return _send_tokens(request, response, access_token, refresh_token, stored)
            return {"success": True}

        @router.delete("/linked-accounts/{provider}/{provider_account_id}")
        async def unlink_account(
            provider: str,
            provider_account_id: str,
            user: AuthUser = Depends(require_auth),
        ) -> dict:
            stored = await store.get_by_id(user.sub)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            metadata = stored.metadata or {}
            linked: list = metadata.get("linkedAccounts", [])
            metadata["linkedAccounts"] = [
                a for a in linked
                if not (a.get("provider") == provider and a.get("providerAccountId") == provider_account_id)
            ]
            stored.metadata = metadata
            await store.update(stored)
            return {"success": True}

        # ── /oauth/* ───────────────────────────────────────────────────────────

        @router.get("/oauth/{provider}", include_in_schema=True)
        async def oauth_start(provider: str, request: Request):
            if not cfg.on_oauth_start:
                raise HTTPException(status_code=404, detail="OAuth provider not configured")
            result = await _resolve_hook_result(cfg.on_oauth_start, provider, request)
            if isinstance(result, str):
                return RedirectResponse(url=result, status_code=302)
            if isinstance(result, dict):
                redirect_to = result.get("redirectTo") or result.get("redirect_to") or result.get("url")
                if isinstance(redirect_to, str) and redirect_to:
                    return RedirectResponse(url=redirect_to, status_code=302)
                return result
            raise HTTPException(status_code=400, detail="Invalid OAuth start hook response")

        @router.get("/oauth/{provider}/callback", include_in_schema=True)
        async def oauth_callback(provider: str, request: Request):
            if not cfg.on_oauth_callback:
                raise HTTPException(status_code=404, detail="OAuth provider not configured")
            try:
                result = await _resolve_hook_result(cfg.on_oauth_callback, provider, request)
            except Exception as exc:
                code = getattr(exc, "code", None) or getattr(exc, "error_code", None)
                detail = getattr(exc, "detail", None)
                if isinstance(detail, dict):
                    err_data = detail.get("data") if isinstance(detail.get("data"), dict) else detail
                    if not code:
                        code = detail.get("error") or detail.get("code")
                else:
                    err_data = getattr(exc, "data", None) or {}
                if (
                    code == "OAUTH_ACCOUNT_CONFLICT"
                    or getattr(exc, "status_code", None) == 409
                    or (isinstance(exc, HTTPException) and exc.status_code == 409)
                ):
                    conflict_data = _oauth_conflict_data(provider, err_data if isinstance(err_data, dict) else {})
                    _emit(
                        AuthEventNames.AUTH_OAUTH_CONFLICT,
                        {"data": conflict_data},
                        request,
                    )
                raise

            redirect_to = "/"
            login_after = True
            user_id: str | None = None

            if isinstance(result, str):
                user_id = result
            elif isinstance(result, StoredUser):
                user_id = result.id
            elif isinstance(result, dict):
                if result.get("error") == "OAUTH_ACCOUNT_CONFLICT" or result.get("code") == "OAUTH_ACCOUNT_CONFLICT":
                    conflict_data = _oauth_conflict_data(provider, result)
                    _emit(
                        AuthEventNames.AUTH_OAUTH_CONFLICT,
                        {"data": conflict_data},
                        request,
                    )
                user_id = result.get("userId") or result.get("user_id")
                if result.get("redirectTo") or result.get("redirect_to"):
                    redirect_to = result.get("redirectTo") or result.get("redirect_to")
                if "login" in result:
                    login_after = bool(result["login"])
            elif result is None:
                raise HTTPException(status_code=400, detail="OAuth callback rejected")
            else:
                raise HTTPException(status_code=400, detail="Invalid OAuth callback hook response")

            redirect = RedirectResponse(url=redirect_to, status_code=302)
            if not login_after:
                return redirect

            if not user_id:
                raise HTTPException(status_code=400, detail="OAuth callback did not resolve user")
            stored = await store.get_by_id(user_id)
            if not stored:
                raise HTTPException(status_code=404, detail="User not found")
            access_token, refresh_token, session = await _create_session(stored, request)
            _set_auth_cookies(
                redirect,
                access_token,
                refresh_token,
                secure=secure,
                same_site=same_site,
                access_expires=access_exp,
                refresh_expires=refresh_exp,
                domain=domain,
                access_cookie_name=access_cookie_name,
                refresh_cookie_name=refresh_cookie_name,
            )
            _emit(
                AuthEventNames.AUTH_OAUTH_SUCCESS,
                {
                    "userId": stored.id,
                    "tenantId": getattr(stored, "tenant_id", None),
                    "sessionId": session.handle if session else None,
                    "data": {
                        "provider": provider,
                        "redirectTo": redirect_to,
                    },
                },
                request,
            )
            return redirect

        # ── /ui/config ───────────────────────────────────────────────────────

        @router.get("/ui/config")
        async def ui_config() -> dict:
            if settings_store:
                config_data = await settings_store.get("ui_config")
                if config_data:
                    return config_data
            return cfg.ui_config or {}

        # ── /tools/stream (SSE) ──────────────────────────────────────────────
        # If cfg.tools is set and has an SseManager, use it; otherwise keep a
        # minimal keep-alive generator for backwards compatibility.

        @router.get("/tools/stream")
        async def tools_stream(
            request: Request,
            user: AuthUser | None = Depends(get_current_user),
        ) -> StreamingResponse:
            tools = getattr(cfg, "tools", None)
            if tools and getattr(tools, "sse", None):
                user_id = user.sub if user else None
                tenant_id = getattr(user, "tenant_id", None) if user else None
                authorised = ["global"]
                if tenant_id:
                    authorised.append(f"tenant:{tenant_id}")
                if user_id:
                    authorised.append(f"user:{user_id}")
                conn = tools.sse.connect(authorised, user_id=user_id, tenant_id=tenant_id)

                import asyncio as _asyncio

                async def _disconnect():
                    try:
                        await request.is_disconnected()
                    except Exception:
                        pass
                    finally:
                        tools.sse.disconnect(conn.id)

                _asyncio.create_task(_disconnect())
                return StreamingResponse(
                    conn.__aiter__(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )

            # Fallback: minimal keep-alive stream (no real SSE manager configured)
            async def _ping():
                yield ": connected\n\n"

            return StreamingResponse(
                _ping(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        # ── /api-keys (API key management) ───────────────────────────────────
        # Only mounted when cfg.api_key_store is set.

        api_key_store = getattr(cfg, "api_key_store", None)
        if api_key_store is not None:
            from .api_keys import ApiKeyService as _ApiKeyService

            _api_key_svc = _ApiKeyService()

            @router.get("/api-keys")
            async def list_api_keys(
                user: AuthUser = Depends(require_auth),
            ) -> dict:
                keys = await api_key_store.list_all(service_id=user.sub)
                return {"keys": [k.to_api_dict() for k in keys]}

            @router.post("/api-keys", status_code=201)
            async def create_api_key(
                request: Request,
                user: AuthUser = Depends(require_auth),
            ) -> dict:
                body: dict = await request.json() if await _has_body(request) else {}
                result = await _api_key_svc.create_key(
                    api_key_store,
                    name=body.get("name", "API Key"),
                    service_id=user.sub,
                    scopes=body.get("scopes", []),
                    allowed_ips=body.get("allowedIps"),
                )
                return {"rawKey": result.raw_key, "key": result.record.to_api_dict()}

            @router.delete("/api-keys/{key_id}")
            async def revoke_api_key(
                key_id: str,
                user: AuthUser = Depends(require_auth),
            ) -> dict:
                key = await api_key_store.find_by_id(key_id)
                if not key or key.service_id != user.sub:
                    raise HTTPException(status_code=404, detail="API key not found")
                await api_key_store.delete(key_id)
                return {"success": True}

        # ── JWKS endpoint (IdP mode) ─────────────────────────────────────────
        if _idp_active and _idp_public_key and _idp_cfg is not None:
            from .idp import JwksService as _JwksService
            _jwks_doc = _JwksService.build_jwks_document(_idp_public_key)

            # Strip the router prefix so the path is relative to where it's mounted
            # The well-known path may start with / — mount relative to the prefix
            _well_known_path = getattr(_idp_cfg, "jwks_path", "/.well-known/jwks.json")
            # Remove the api_prefix from the path if it's already included
            if _well_known_path.startswith(cfg.api_prefix):
                _jwks_route_path = _well_known_path[len(cfg.api_prefix):]
            else:
                _jwks_route_path = _well_known_path

            @router.get(_jwks_route_path, include_in_schema=True)
            async def jwks() -> dict:
                """Public JSON Web Key Set — allows Resource Servers to verify RS256 tokens."""
                return _jwks_doc

        return router

async def _has_body(request: Request) -> bool:
    return int(request.headers.get("content-length", "0")) > 0
