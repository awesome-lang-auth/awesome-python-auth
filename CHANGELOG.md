# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-10-08

### Added

- Identity events are published automatically (#13): the auth router publishes login
  (success and failure), logout, session rotation, user created/deleted, password
  changed, email verified/changed, 2FA enabled/disabled and OAuth success/conflict
  events, and the admin router publishes role assigned/revoked, to the `AuthEventBus`
  passed as the new `event_bus` argument of `AuthConfigurator.router()` /
  `build_admin_router()` or set on the new `AuthConfig.event_bus` field (the auth router
  also falls back to `AuthConfig.tools.event_bus`). New event name
  `AuthEventNames.USER_EMAIL_CHANGED` (`identity.user.email.changed`).

### Changed

- Package description now names the current client libraries,
  `@awesome-lang-auth/angular` and `awesome_flutter_auth`.
- Project URLs: added Homepage, Documentation and Changelog; Repository and Issues point
  to the `awesome-lang-auth` GitHub organization (#11).
- Admin `POST /api/users/{user_id}/roles` now passes an optional `tenantId` from the
  request body to `RolesPermissionsStore.add_role_to_user(..., tenant_id=...)`; it was
  ignored before (#13).

### Fixed

- `POST /change-email/confirm` in cookie mode no longer fails with a server error when it
  re-issues the auth cookies (#13).
- Test-only: the router tests pass with pytest-asyncio 1.4.0 (#12).

---

## [1.1.0] - 2026-05-06

### Added

#### AuthEventBus (mirrors awesome-node-auth)
- `AuthEventBus` — lightweight publish/subscribe bus for identity events.  Both sync and
  async handlers supported; wildcard topic `'*'` receives every event.
- `AuthEventNames` — standard event name constants following the `domain.resource.action`
  convention (`identity.auth.login.success`, `identity.user.created`, etc.).
- `AuthEventPayload` — type alias for the event dict published on the bus.
- `AuthTools` now accepts `event_bus: AuthEventBus` — `track()` automatically publishes
  every event onto the bus so external listeners (audit logs, analytics, etc.) can react
  without coupling to the auth flow.

#### Multi-channel `notify()` (mirrors awesome-node-auth >= 1.8.0)
- `AuthTools.notify()` now supports `channels` parameter: `'sse'` (default), `'email'`,
  and `'sms'`.
- `NotificationService` — thin facade wrapping `MailerService` and `SmsService` for
  transport-agnostic notifications.
- `SmsService` — HTTP GET SMS gateway client (mirrors `SmsService` from awesome-node-auth).
- `SmsConfig` — configuration dataclass for the SMS transport.
- `SendEmailOptions` / `SendSmsOptions` — options dataclasses for `NotificationService`.
- `AuthTools` now accepts `email_config: MailerConfig`, `sms_config: SmsConfig`, and
  `user_store: UserStore` to enable email and SMS notification channels.

#### Identity Provider (IdP) mode (mirrors awesome-node-auth)
- `IdProviderConfig` — dataclass that activates RS256/RSA-2048 IdP mode.  When set on
  `AuthConfig.id_provider`, the auth router signs JWTs with RS256 and exposes a public
  JWKS endpoint (`GET {api_prefix}/.well-known/jwks.json`).
- Auto-generation of an ephemeral RSA keypair for development (with a startup warning).
- `ResourceServerConfig` — dataclass that activates Resource Server mode.  When set on
  `AuthConfig.resource_server`, auth dependencies validate tokens against a remote JWKS
  URL instead of the local HS256 secret.
- `JwksService` — utility class for RSA keypair generation, PEM ↔ JWK conversion, and
  JWKS document building.
- `JwksClient` — async cached HTTP client for fetching remote JWKS endpoints (used by
  Resource Server mode).
- `JWK` — JWK data object.
- `jwt_utils`: new helpers `create_idp_access_token()`, `create_idp_refresh_token()`, and
  `decode_token_with_jwks()` for RS256 token creation and JWKS-based verification.
- `get_current_user`, `require_auth`, `require_roles` now automatically switch to
  JWKS-based RS256 verification when Resource Server mode is active.

---

## [1.0.0] - 2026-05-05

### Added

- Initial release of `awesome-python-auth`.
- FastAPI authentication library fully compatible with [ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth) (Angular) and [awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter) (Flutter).
- Cookie-based auth (HttpOnly `access-token` + `refresh-token`) for Angular/web clients.
- Bearer token auth (`X-Auth-Strategy: bearer`) for Flutter native clients.
- CSRF protection via `CsrfMiddleware`.
- TOTP two-factor authentication.
- Magic-link and SMS/OTP login flows.
- Password reset, email verification, and email change flows.
- Session management (list & revoke sessions).
- Account linking for OAuth providers.
- RBAC support via `RolesPermissionsStore`.
- Multi-tenancy support via `TenantStore`.
- Token store with TTL (`TokenStore`).
- Linked accounts store (`LinkedAccountsStore`, `PendingLinkStore`).
- Admin router (`build_admin_router`).
- UI router (`build_ui_router`) serving bundled HTML/CSS/JS assets.
- Tools router (`build_tools_router`) with Server-Sent Events (`SseManager`).
- API key support (`ApiKeyService`).
- Webhook sender (`WebhookSender`).
- In-memory store implementations for all extension points.
- GitHub Actions CI (Python 3.11 & 3.12) and PyPI publish via OIDC Trusted Publishing.
