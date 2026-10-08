"""Configuration dataclass for awesome-python-auth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from .models import StoredUser, UserStore

#: Default URL prefix of the auth API, the same on every awesome-lang-auth backend.
#: The built-in UI is served under ``<prefix>/ui`` (``/auth/ui/login``,
#: ``/auth/ui/auth.js``).  Until 1.x it was ``"/api/auth"``.
DEFAULT_API_PREFIX = "/auth"


@dataclass
class AuthConfig:
    """Configuration for the awesome-python-auth backend.

    Parameters
    ----------
    api_prefix:
        URL prefix where the auth router will be mounted.
        Must match the ``apiPrefix`` setting in ``ng-awesome-node-auth`` /
        ``AuthOptions.apiPrefix`` in ``awesome-node-auth-flutter``.
        The built-in UI (:func:`~awesome_python_auth.ui_router.mount_ui`) is
        served under ``<api_prefix>/ui``.
        Default: ``"/auth"`` (``"/api/auth"`` until 1.x; pass
        ``api_prefix="/api/auth"`` to keep the old routes).
    access_token_secret:
        Secret used to sign JWT access tokens.  Keep this private.
    access_token_expires_in:
        Access-token lifetime in seconds.  Default: 900 (15 minutes).
    refresh_token_expires_in:
        Refresh-token lifetime in seconds.  Default: 604800 (7 days).
    cookie_secure:
        Set the ``Secure`` flag on auth cookies.  Default: ``True``.
        Set to ``False`` only during local HTTP development.
    cookie_same_site:
        ``SameSite`` attribute for auth cookies.  Default: ``"lax"``.
    cookie_domain:
        Optional domain for auth cookies.  Leave ``None`` for same-origin.
    cookie_prefix:
        Optional cookie name prefix.  Set to ``"__Host-"`` or ``"__Secure-"``
        for hardened cookie naming parity with awesome-node-auth.
    totp_issuer:
        Issuer name shown in authenticator apps.  Default: ``"awesome-python-auth"``.
    ui_config:
        Static UI configuration returned by ``GET <api_prefix>/ui/config``.
    email:
        Optional email configuration dict.  Keys depend on the provider.
        Pass ``{"enabled": True}`` to signal that email sending is active.

    Hooks
    -----
    The following optional async callables allow you to plug in side-effects
    without subclassing the router:

    on_forgot_password(user, token):
        Called with the ``StoredUser`` and the raw reset token.  Send the email here.

    on_send_verification_email(user, token):
        Called with the ``StoredUser`` and the raw verification token.

    on_request_email_change(user, new_email, token):
        Called when a user requests an email address change.

    on_magic_link_send(email, temp_token, mode):
        Called when a magic-link send is requested.

    on_magic_link_verify(token, mode) -> user_id | None:
        Called with the raw magic-link token.  Return the user ID to log in, or
        ``None`` to reject.

    on_sms_send(email, temp_token, mode):
        Called when an SMS OTP send is requested.

    on_sms_verify(user_id, temp_token, code, mode) -> user_id | None:
        Called to verify an SMS OTP.  Return the user ID on success.

    on_link_request(email, provider, current_user):
        Called when account-linking is initiated.

    on_link_verify(token, provider, login_after_linking) -> user_id | None:
        Called to verify an account-linking token.

    on_oauth_start(provider, request) -> redirect_url:
        Called by ``GET /oauth/{provider}``. Return the provider authorization URL.

    on_oauth_callback(provider, request) -> user_id | dict | StoredUser | None:
        Called by ``GET /oauth/{provider}/callback``. Return the local user identity
        (or a dict containing ``userId``/``redirectTo`` fields) to complete login.

    on_register(stored_user):
        Optional hook called immediately after a successful registration.
        Use it to send welcome emails, provision resources, etc.

    mailer:
        Optional :class:`~awesome_python_auth.mailer.MailerConfig` instance.
        When provided, the library uses :class:`~awesome_python_auth.mailer.MailerService`
        for all transactional emails (password reset, verification, magic link, etc.)
        in addition to the hook callbacks.

    tools:
        Optional :class:`~awesome_python_auth.tools.AuthTools` instance.
        When provided, auth events are tracked (telemetry, SSE, webhooks).

    api_key_store:
        Optional :class:`~awesome_python_auth.api_keys.ApiKeyStore` instance.
        When provided, ``GET /api-keys``, ``POST /api-keys``, and
        ``DELETE /api-keys/{id}`` endpoints are enabled.
    id_provider:
        Optional :class:`~awesome_python_auth.idp.IdProviderConfig`.
        When set, the router signs JWTs with **RS256** and exposes a
        ``GET /.well-known/jwks.json`` JWKS endpoint so downstream Resource
        Servers can verify tokens without a shared secret.
    resource_server:
        Optional :class:`~awesome_python_auth.idp.ResourceServerConfig`.
        When set, auth dependencies validate incoming tokens against a remote
        JWKS endpoint (issued by a central IdP) instead of the local HS256
        secret.
    """

    api_prefix: str = DEFAULT_API_PREFIX
    access_token_secret: str = ""
    access_token_expires_in: int = 900
    refresh_token_expires_in: int = 604800
    cookie_secure: bool = True
    cookie_same_site: str = "lax"
    cookie_domain: str | None = None
    cookie_prefix: str | None = None
    totp_issuer: str | None = None
    ui_config: dict[str, Any] | None = None
    email: dict[str, Any] | None = None

    # ── Mailer ───────────────────────────────────────────────────────────────
    # Optional: provide a MailerConfig to enable built-in email sending.
    # When set, the library will use MailerService for all transactional emails.
    mailer: Any = None  # MailerConfig | None

    # ── AuthTools integration ─────────────────────────────────────────────────
    # Optional: provide an AuthTools instance to enable telemetry, SSE, webhooks.
    tools: Any = None  # AuthTools | None

    # ── Event bus integration ────────────────────────────────────────────────
    # Optional: provide an AuthEventBus instance for auto-publishing auth events.
    event_bus: Any = None  # AuthEventBus | None

    # ── API Keys ─────────────────────────────────────────────────────────────
    # Optional: provide an ApiKeyStore to enable API key auth on /api-keys/* endpoints.
    api_key_store: Any = None  # ApiKeyStore | None

    # ── ReBAC / RBAC ─────────────────────────────────────────────────────────
    # Optional: provide a RolesPermissionsStore to automatically enrich JWT tokens
    # with roles and permissions at login/refresh time.
    roles_permissions_store: Any = None  # RolesPermissionsStore | None

    # ── Multi-tenancy ─────────────────────────────────────────────────────────
    # Optional: provide a TenantStore to enable multi-tenant support.
    tenant_store: Any = None  # TenantStore | None

    # ── IdP / Resource Server ──────────────────────────────────────────────────
    # Optional: provide an IdProviderConfig to enable RS256 / JWKS IdP mode.
    id_provider: Any = None  # IdProviderConfig | None

    # Optional: provide a ResourceServerConfig to verify tokens via remote JWKS.
    resource_server: Any = None  # ResourceServerConfig | None

    # ── Stateful session checks ────────────────────────────────────────────────
    # When using stateful sessions, choose where revocation checks happen:
    # - "allcalls": every authenticated request
    # - "refresh": only on /refresh
    # - "none": no extra session existence checks
    session_check_on: str = "none"

    # ── Hooks ────────────────────────────────────────────────────────────────
    on_forgot_password: Any = None
    on_send_verification_email: Any = None
    on_request_email_change: Any = None
    on_magic_link_send: Any = None
    on_magic_link_verify: Any = None
    on_sms_send: Any = None
    on_sms_verify: Any = None
    on_link_request: Any = None
    on_link_verify: Any = None
    on_oauth_start: Any = None
    on_oauth_callback: Any = None
    on_register: Any = None  # async (stored_user) -> None  — called after registration


# Import here to avoid circular dependency
from .router import AuthConfigurator  # noqa: E402

__all__ = ["AuthConfig", "AuthConfigurator", "DEFAULT_API_PREFIX"]
