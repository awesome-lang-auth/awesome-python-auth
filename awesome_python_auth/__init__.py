"""
awesome-python-auth
===================
FastAPI authentication library compatible with:
- ng-awesome-node-auth (Angular)
- awesome-node-auth-flutter (Dart/Flutter)

Usage::

    from awesome_python_auth import AuthConfigurator, AuthConfig, UserStore, mount_ui

    config = AuthConfig(
        access_token_secret="your-secret",  # api_prefix defaults to "/auth"
    )
    configurator = AuthConfigurator(config, user_store)
    app.include_router(configurator.router())  # /auth/login, /auth/me, ...
    mount_ui(app, config)                      # /auth/ui/login, /auth/ui/auth.js
"""

from .config import DEFAULT_API_PREFIX, AuthConfig, AuthConfigurator
from .dependencies import get_current_user, require_auth, require_roles
from .models import AuthUser, SessionInfo, UserStore, SettingsStore, StoredUser, StoredSession, InMemoryUserStore
from .middleware import CsrfMiddleware
from .exceptions import AuthError, NotAuthenticatedError, ForbiddenError
from .mailer import MailerConfig, MailerService, TemplateStore
from .api_keys import ApiKey, ApiKeyService, ApiKeyStore, InMemoryApiKeyStore
from .webhooks import (
    WebhookConfig,
    WebhookStore,
    InMemoryWebhookStore,
    WebhookSender,
    OutgoingWebhookEvent,
)
from .sse import SseManager, StreamEvent
from .tools import AuthTools, TelemetryStore, TelemetryEvent, InMemoryTelemetryStore
from .tools_router import build_tools_router
from .ui_router import build_ui_router, mount_ui, ui_mount_path
from .rebac import RolesPermissionsStore, InMemoryRolesPermissionsStore
from .tenants import Tenant, TenantStore, InMemoryTenantStore
from .token_store import TokenStore, InMemoryTokenStore
from .linked_accounts import (
    LinkedAccount,
    LinkedAccountsStore,
    InMemoryLinkedAccountsStore,
    PendingLink,
    PendingLinkStore,
    InMemoryPendingLinkStore,
)
from .admin_router import build_admin_router
from .events import AuthEventBus, AuthEventNames, AuthEventPayload
from .notification import (
    NotificationService,
    SmsConfig,
    SmsService,
    SendEmailOptions,
    SendSmsOptions,
)
from .idp import (
    IdProviderConfig,
    ResourceServerConfig,
    JwksService,
    JwksClient,
    JWK,
)

__all__ = [
    # Core
    "AuthConfig",
    "AuthConfigurator",
    "DEFAULT_API_PREFIX",
    "AuthUser",
    "SessionInfo",
    "UserStore",
    "SettingsStore",
    "StoredUser",
    "StoredSession",
    "InMemoryUserStore",
    "CsrfMiddleware",
    # Dependencies
    "get_current_user",
    "require_auth",
    "require_roles",
    # Exceptions
    "AuthError",
    "NotAuthenticatedError",
    "ForbiddenError",
    # Mailer
    "MailerConfig",
    "MailerService",
    "TemplateStore",
    # API keys
    "ApiKey",
    "ApiKeyService",
    "ApiKeyStore",
    "InMemoryApiKeyStore",
    # Webhooks
    "WebhookConfig",
    "WebhookStore",
    "InMemoryWebhookStore",
    "WebhookSender",
    "OutgoingWebhookEvent",
    # SSE
    "SseManager",
    "StreamEvent",
    # Tools (telemetry + SSE + webhooks + event bus)
    "AuthTools",
    "TelemetryStore",
    "TelemetryEvent",
    "InMemoryTelemetryStore",
    "build_tools_router",
    # UI
    "build_ui_router",
    "mount_ui",
    "ui_mount_path",
    # RBAC / ReBAC
    "RolesPermissionsStore",
    "InMemoryRolesPermissionsStore",
    # Tenants
    "Tenant",
    "TenantStore",
    "InMemoryTenantStore",
    # Token store
    "TokenStore",
    "InMemoryTokenStore",
    # Linked accounts
    "LinkedAccount",
    "LinkedAccountsStore",
    "InMemoryLinkedAccountsStore",
    "PendingLink",
    "PendingLinkStore",
    "InMemoryPendingLinkStore",
    # Admin router
    "build_admin_router",
    # Event bus
    "AuthEventBus",
    "AuthEventNames",
    "AuthEventPayload",
    # Notification service
    "NotificationService",
    "SmsConfig",
    "SmsService",
    "SendEmailOptions",
    "SendSmsOptions",
    # IdP / Resource Server / JWKS
    "IdProviderConfig",
    "ResourceServerConfig",
    "JwksService",
    "JwksClient",
    "JWK",
]
