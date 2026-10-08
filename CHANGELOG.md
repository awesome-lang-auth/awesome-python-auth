# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2.0.0

### BREAKING CHANGES

- The default API prefix is now `/auth` (it was `/api/auth`), the same as every other
  awesome-lang-auth backend. `AuthConfig.api_prefix` and `CsrfMiddleware(api_prefix=...)`
  both default to `/auth`; the new constant `DEFAULT_API_PREFIX` holds it. Routes,
  payloads and cookies are otherwise unchanged. To keep the 1.x routes, set the prefix
  explicitly on both:

  ```python
  config = AuthConfig(api_prefix="/api/auth", access_token_secret="...")
  app.add_middleware(CsrfMiddleware, api_prefix="/api/auth")
  ```

  Change both or neither: if `AuthConfig.api_prefix` and `CsrfMiddleware(api_prefix=...)`
  differ, CSRF is not enforced on the auth routes and nothing warns. An app that already
  passes `api_prefix="/api/auth"` to `AuthConfig` only must now pass it to
  `CsrfMiddleware` too. To adopt `/auth`, remove `api_prefix` from both.

- FastAPI derives OpenAPI `operationId`s from the route path, so with the new default
  they change too (`disable_2fa_api_auth_2fa_disable_post` becomes
  `disable_2fa_auth_2fa_disable_post`). Clients generated from the OpenAPI document
  keep their method names if you pin `api_prefix="/api/auth"`.

- `GET <api_prefix>/ui/config` on the auth router returns the awesome-node-auth
  document that `auth.js` reads (`apiPrefix`, `features`, `ui`, `headless`) instead of
  the raw `AuthConfig.ui_config` dict (`{}` by default). `ui_config` (or the
  `"ui_config"` entry of the `settings_store` passed to `router()`) is read as
  `{"features": {...}, "ui": {...}, "headless": bool}`; other keys are no longer
  returned. Apps that
  stored their own data in `ui_config` and read it back from this endpoint must serve
  it from a route of their own.

### Added

- `AuthConfigurator.router()` serves the browser runtime: `GET <api_prefix>/ui/auth.js`
  (the awesome-node-auth `auth.js`, byte for byte) and `GET <api_prefix>/ui/config`
  answer as soon as the router is included, at `/auth/ui/auth.js` by default and
  under a custom prefix with it (`/api/auth/ui/auth.js`), as on every
  awesome-lang-auth backend. Without the pages, `/ui/login` answers 404 while
  `auth.js` answers 200. `/ui/config` reports `headless` from
  `ui_config["headless"]` (`false` unless set), as awesome-node-auth reports
  `ui.headless`; SPAs with their own login pages set it.
- `mount_ui(app, config)` mounts the optional built-in pages under `<api_prefix>/ui`
  (`/auth/ui/login` by default). `auth.js` derives the API prefix from the page URL,
  as on awesome-node-auth. `ui_mount_path(prefix)` returns the mount path.
- `build_ui_router()` and `mount_ui()` take a `settings_store`, read like the router's
  for `/config` and the pages.

### Changed

- `CsrfMiddleware` matches its prefix on whole path segments: with `/auth` it checks
  `/auth` and `/auth/...`, not unrelated routes such as `/authors`.
- An app mounted at `<api_prefix>/ui` (`mount_ui`, or `build_ui_router()` mounted by
  hand) serves everything under that path, `auth.js` and `/config` included, whether
  it is added before or after the auth router; the router's two routes step aside.
  Its `/config` reports its own `headless` switch (`false` when it serves the pages).
- The built-in UI serves the bundled `auth.js` when a custom `ui_assets_dir` has none.
- `features.register` in `/ui/config` is also `true` when `router(on_register=...)`
  is set, as with awesome-node-auth's `onRegister`.

### Fixed

- The auth router's own `GET <api_prefix>/ui/config` no longer hides the built-in UI's
  node-shaped one: with the UI mounted at `<api_prefix>/ui`, the endpoint returned the
  raw `ui_config` (`{}`) whenever the router had been included first.

- The bundled `auth.js` had lost its first line (`/**`), so browsers rejected it with a
  syntax error and `window.AwesomeNodeAuth` was never defined. It is again the
  awesome-node-auth runtime byte for byte (the file shipped in `@awesome-lang-auth/node`
  1.10.8); a test pins its sha256, checks the served bytes, and runs `node --check` on
  them when Node.js is available.

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
