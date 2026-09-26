# awesome-python-auth

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**FastAPI authentication library** that replicates the [awesome-node-auth](https://github.com/awesome-lang-auth/awesome-node-auth) Node.js backend in Python.

Fully compatible with:
- **[ng-awesome-node-auth](https://github.com/awesome-lang-auth/awesome-angular-auth)** — Angular client library
- **[awesome-node-auth-flutter](https://github.com/awesome-lang-auth/awesome-flutter-auth)** — Flutter/Dart client library

Supports **both authentication strategies** used by those clients:
| Platform | Strategy | Token |
|---|---|---|
| Angular / Web | Cookie (HttpOnly) + CSRF | `access-token` cookie + `X-CSRF-Token` header |
| Flutter Native (iOS/Android/Desktop) | Bearer token | `Authorization: Bearer <token>` + `X-Auth-Strategy: bearer` |

## Parity Snapshot vs `awesome-node-auth`

| Capability | Status in `awesome-python-auth` | Notes |
|---|---|---|
| Auth strategies (email/password, magic link, SMS OTP, TOTP 2FA, OAuth linking) | ✅ Implemented | Includes dedicated OAuth provider endpoints: `/oauth/{provider}` and `/oauth/{provider}/callback`. |
| Token management (cookie/bearer, access/refresh rotation, secure cookies) | ✅ Implemented | Cookie + bearer mode, rotation, and optional `__Host-` / `__Secure-` cookie-prefix parity via `AuthConfig.cookie_prefix`. |
| Identity Provider (IdP) mode (RS256 + JWKS + resource server validation) | ✅ Implemented | `id_provider` + `resource_server` config enables RS256 JWT issuance, `/.well-known/jwks.json`, and remote JWKS validation. |
| Stateful sessions | ✅ Implemented | Session lifecycle is implemented with revocation checks configurable via `AuthConfig.session_check_on` (`allcalls` / `refresh` / `none`). |
| Dynamic email templates + UI i18n fallback | ✅ Implemented | `TemplateStore` is supported and bundled UI i18n keys provide fallback. |
| CSRF protection | ✅ Implemented | `CsrfMiddleware` uses cookie + header double-submit validation for browser flows. |
| Account management | ✅ Implemented | Registration, profile update, password/email change, verification, and account deletion are available. |
| Account linking | ✅ Implemented | Link request/verify plus linked-account management endpoints are available. |
| RBAC | ✅ Implemented | `RolesPermissionsStore` with token enrichment and role-based dependencies. |
| Multi-tenancy | ✅ Implemented | `TenantStore` and tenant-aware models are available. |
| Admin panel | ✅ Implemented | `build_admin_router(...)` serves the bundled admin SPA and APIs. |
| Built-in UI + auth runtime (`auth.js`) | ✅ Implemented | `build_ui_router(...)` serves bundled pages/assets with runtime helpers. |
| Client libraries compatibility (Angular + Flutter) | ✅ Implemented | Cookie+CSRF (web) and bearer (native) client strategies are both supported. |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify channels) | ✅ Implemented | `AuthTools`, `AuthEventBus`, SSE, webhooks, telemetry, and `notify()` channels are available. |
| API keys (M2M) | ✅ Implemented | `ApiKeyService`/`ApiKeyStore` plus auth/admin API-key endpoints are available. |
| OpenAPI / Swagger docs | ✅ Implemented | FastAPI auto-generates OpenAPI and Swagger UI for auth/admin/tools routers. |
| MCP server (`awesome-node-auth-mcp-server`) | ➖ Out of scope | No Python-side MCP server is bundled in this repository. |

---

## Installation

```bash
pip install awesome-python-auth
```

---

## Quick Start

```python
from fastapi import FastAPI
from awesome_python_auth import AuthConfig, AuthConfigurator, CsrfMiddleware
from awesome_python_auth.models import InMemoryUserStore

app = FastAPI()

# 1. Configure
user_store = InMemoryUserStore()
config = AuthConfig(
    api_prefix="/api/auth",
    access_token_secret="your-secret-here",  # must match the Angular/Flutter client config
)

# 2. Add CSRF middleware (required for Angular web clients)
app.add_middleware(CsrfMiddleware, api_prefix="/api/auth")

# 3. Mount the auth router
configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())
```

Point Angular/Flutter clients at `http://your-server/api/auth` — no other changes needed.

---

## AuthConfig

```python
from awesome_python_auth import AuthConfig

config = AuthConfig(
    api_prefix="/api/auth",          # Must match client's apiPrefix
    access_token_secret="secret",   # JWT signing secret (keep private!)
    access_token_expires_in=900,    # Access token lifetime (seconds, default 15 min)
    refresh_token_expires_in=604800,# Refresh token lifetime (seconds, default 7 days)
    cookie_secure=True,             # Set Secure flag on cookies (False for local HTTP)
    cookie_same_site="lax",         # SameSite cookie attribute
    cookie_domain=None,             # Cookie domain (None = same origin)
    cookie_prefix="__Host-",        # Optional cookie name prefix (__Host- / __Secure-)
    totp_issuer="My App",           # Shown in authenticator apps
    session_check_on="refresh",     # Stateful-session revocation checks: allcalls|refresh|none
    ui_config={"theme": "dark"},    # Static UI config returned by GET /ui/config
)
```

---

## Custom User Store

Implement `UserStore` to connect to your database:

```python
from awesome_python_auth import UserStore
from awesome_python_auth.models import StoredUser

class MySQLUserStore(UserStore):
    async def get_by_email(self, email: str) -> StoredUser | None:
        row = await db.fetchone("SELECT * FROM users WHERE email = ?", [email])
        return StoredUser(**row) if row else None

    async def get_by_id(self, user_id: str) -> StoredUser | None:
        row = await db.fetchone("SELECT * FROM users WHERE id = ?", [user_id])
        return StoredUser(**row) if row else None

    async def create(self, user: StoredUser) -> StoredUser:
        await db.execute("INSERT INTO users ...", [...])
        return user

    async def update(self, user: StoredUser) -> StoredUser:
        await db.execute("UPDATE users SET ...", [...])
        return user

    async def delete(self, user_id: str) -> None:
        await db.execute("DELETE FROM users WHERE id = ?", [user_id])
```

---

## Protecting Your Routes

```python
from fastapi import Depends, FastAPI
from awesome_python_auth import get_current_user, require_auth, require_roles
from awesome_python_auth.models import AuthUser

app = FastAPI()

# Optional auth (returns None when unauthenticated)
@app.get("/public")
async def public(user: AuthUser | None = Depends(get_current_user)):
    return {"user": user}

# Required auth (raises 401 when unauthenticated)
@app.get("/profile")
async def profile(user: AuthUser = Depends(require_auth)):
    return user.to_api_dict()

# Role-based access
@app.delete("/admin-only")
async def admin_only(user: AuthUser = Depends(require_roles(["admin"]))):
    return {"ok": True}
```

---

## API Endpoints

All endpoints are mounted under `api_prefix` (default: `/api/auth`).

### Session
| Method | Path | Description |
|---|---|---|
| `GET` | `/me` | Return the current authenticated user |
| `POST` | `/login` | Login with email + password |
| `POST` | `/register` | Create a new account |
| `POST` | `/logout` | Logout and clear cookies |
| `POST` | `/refresh` | Refresh the access token |
| `PATCH` | `/profile` | Update first/last name |
| `DELETE` | `/account` | Delete the current account |

### Password
| Method | Path | Description |
|---|---|---|
| `POST` | `/forgot-password` | Initiate password recovery |
| `POST` | `/reset-password` | Reset password with token |
| `POST` | `/change-password` | Change password (authenticated) |
| `POST` | `/send-verification-email` | Resend email verification |
| `GET` | `/verify-email?token=` | Verify email address |
| `POST` | `/change-email/request` | Request email address change |
| `POST` | `/change-email/confirm` | Confirm email address change |

### Two-Factor Authentication (TOTP)
| Method | Path | Description |
|---|---|---|
| `POST` | `/2fa/setup` | Begin TOTP setup (returns QR code + secret) |
| `POST` | `/2fa/verify-setup` | Confirm TOTP setup |
| `POST` | `/2fa/verify` | Verify TOTP code during login |
| `POST` | `/2fa/disable` | Disable TOTP |

### Magic Link
| Method | Path | Description |
|---|---|---|
| `POST` | `/magic-link/send` | Send a magic-link email |
| `POST` | `/magic-link/verify` | Verify magic-link token |

### SMS / OTP
| Method | Path | Description |
|---|---|---|
| `POST` | `/sms/send` | Send an SMS OTP |
| `POST` | `/sms/verify` | Verify SMS OTP |
| `POST` | `/add-phone` | Add phone number to account |

### Sessions
| Method | Path | Description |
|---|---|---|
| `GET` | `/sessions` | List all active sessions |
| `DELETE` | `/sessions/{handle}` | Revoke a session |

### OAuth
| Method | Path | Description |
|---|---|---|
| `GET` | `/oauth/{provider}` | Start provider OAuth flow (redirect via `on_oauth_start`) |
| `GET` | `/oauth/{provider}/callback` | Complete provider callback and create session via `on_oauth_callback` |

### Account Linking
| Method | Path | Description |
|---|---|---|
| `POST` | `/link-request` | Initiate account linking |
| `POST` | `/link-verify` | Verify linking token |
| `GET` | `/linked-accounts` | List linked OAuth providers |
| `DELETE` | `/linked-accounts/{provider}/{id}` | Unlink a provider |

### Utilities
| Method | Path | Description |
|---|---|---|
| `GET` | `/ui/config` | UI configuration (theme, branding) |
| `GET` | `/tools/stream` | Server-Sent Events stream |

---

## Hooks / Callbacks

Plug in side-effects (email sending, SMS, OAuth) without subclassing:

```python
from awesome_python_auth.models import StoredUser

async def send_password_reset_email(user: StoredUser, token: str) -> None:
    link = f"https://myapp.com/reset-password?token={token}"
    await email_client.send(user.email, "Reset your password", link)

async def verify_magic_link(token: str, mode: str) -> str | None:
    """Return user_id on success, None on failure."""
    return await magic_link_store.verify(token)

config = AuthConfig(
    access_token_secret="secret",
    on_forgot_password=send_password_reset_email,
    on_send_verification_email=send_verification_email,
    on_magic_link_send=send_magic_link_email,
    on_magic_link_verify=verify_magic_link,
    on_sms_send=send_sms_otp,
    on_sms_verify=verify_sms_otp,
    on_link_request=handle_link_request,
    on_link_verify=handle_link_verify,
)
```

---

## Custom `on_register` hook

```python
async def my_on_register(user: StoredUser) -> StoredUser:
    user.role = "user"
    await user_store.create(user)
    await send_welcome_email(user.email)
    return user

app.include_router(configurator.router(on_register=my_on_register))
```

---

## CSRF Middleware

The `CsrfMiddleware` is required when Angular web clients are used. It:

1. Sets a `csrf-token` cookie (readable by JavaScript) on every response.
2. Validates the `X-CSRF-Token` request header for mutating requests (POST, PATCH, DELETE) to `api_prefix`.
3. Automatically skips validation for auth-flow endpoints (login, register, etc.) and for Bearer-token requests from native clients.

```python
app.add_middleware(
    CsrfMiddleware,
    api_prefix="/api/auth",
    cookie_secure=True,     # Set False for local HTTP development
    cookie_same_site="lax",
)
```

---

## AuthEventBus

The `AuthEventBus` is a lightweight publish/subscribe bus that lets you react to identity events (login, register, role change, …) without coupling your code to the auth internals.  Both sync and async handlers are supported.

```python
from awesome_python_auth import AuthEventBus, AuthEventNames

bus = AuthEventBus()

# Sync handler
def on_login(payload):
    print("Login:", payload["userId"], payload["timestamp"])

bus.on_event(AuthEventNames.AUTH_LOGIN_SUCCESS, on_login)

# Async handler
async def async_on_login(payload):
    await audit_log.write(payload["event"], payload["userId"])

bus.on_event(AuthEventNames.AUTH_LOGIN_SUCCESS, async_on_login)

# Wildcard — receives EVERY event
bus.on_event("*", lambda p: metrics.increment(p["event"]))

# Unsubscribe
bus.off_event(AuthEventNames.AUTH_LOGIN_SUCCESS, on_login)
```

Pass the bus to `AuthTools` so `track()` automatically publishes on it:

```python
from awesome_python_auth import AuthTools

tools = AuthTools(event_bus=bus)
await tools.track(AuthEventNames.AUTH_LOGIN_SUCCESS, user_id="u1")
# → on_login is called with {"event": "identity.auth.login.success", "userId": "u1", ...}
```

### Standard event names

All constants live on `AuthEventNames`:

| Constant | Value |
|---|---|
| `AUTH_LOGIN_SUCCESS` | `identity.auth.login.success` |
| `AUTH_LOGIN_FAILED` | `identity.auth.login.failed` |
| `AUTH_LOGOUT` | `identity.auth.logout` |
| `USER_CREATED` | `identity.user.created` |
| `USER_DELETED` | `identity.user.deleted` |
| `USER_EMAIL_VERIFIED` | `identity.user.email.verified` |
| `USER_PASSWORD_CHANGED` | `identity.user.password.changed` |
| `USER_2FA_ENABLED` | `identity.user.2fa.enabled` |
| `USER_2FA_DISABLED` | `identity.user.2fa.disabled` |
| `SESSION_CREATED` | `identity.session.created` |
| `SESSION_REVOKED` | `identity.session.revoked` |
| `ROLE_ASSIGNED` | `identity.role.assigned` |
| `ROLE_REVOKED` | `identity.role.revoked` |

---

## AuthTools — multi-channel `notify()`

`AuthTools.notify()` now supports multiple delivery channels: **SSE** (default), **email**, and **SMS**.

```python
from awesome_python_auth import AuthTools, SseManager
from awesome_python_auth.mailer import MailerConfig
from awesome_python_auth.notification import SmsConfig

tools = AuthTools(
    sse=SseManager(),
    email_config=MailerConfig(
        endpoint="https://mailer.example.com/send",
        api_key="mailer-key",
        from_address="no-reply@example.com",
    ),
    sms_config=SmsConfig(
        endpoint="https://sms.example.com/send",
        api_key="sms-key",
        username="user",
        password="pass",
    ),
    user_store=user_store,  # needed for email/sms channels
)

# SSE only (default)
await tools.notify("user:123", type="ping", data={"msg": "Hello!"})

# Email + SSE
await tools.notify(
    "user:123",
    type="subscription_expiring",
    data={"days": 3},
    user_id="123",
    channels=["sse", "email"],
    email_subject="Your subscription expires soon",
)

# All three channels
await tools.notify(
    "user:123",
    type="alert",
    data="Unusual login detected",
    user_id="123",
    channels=["sse", "email", "sms"],
    email_subject="Security alert",
    sms_message="Unusual login detected on your account",
)
```

### NotificationService

For standalone use (outside `AuthTools`):

```python
from awesome_python_auth import NotificationService, SmsConfig, SendEmailOptions, SendSmsOptions
from awesome_python_auth.mailer import MailerConfig

service = NotificationService(
    email=MailerConfig(endpoint="...", api_key="...", from_address="..."),
    sms=SmsConfig(endpoint="...", api_key="...", username="...", password="..."),
)

await service.send_email(SendEmailOptions(
    to="alice@example.com",
    subject="Hello",
    html="<p>Hi Alice!</p>",
))

await service.send_sms(SendSmsOptions(
    to="+15551234567",
    message="Your OTP is 123456",
))
```

---

## Identity Provider (IdP) mode

When `id_provider` is configured, the auth server becomes a **central Identity Provider**:

- Signs JWTs with **RS256** (RSA-2048) instead of HS256.
- Exposes a public `GET /.well-known/jwks.json` JWKS endpoint.
- Downstream Resource Servers can verify tokens without a shared secret.

```python
import os
from awesome_python_auth import AuthConfig, AuthConfigurator
from awesome_python_auth.idp import IdProviderConfig

config = AuthConfig(
    api_prefix="/api/auth",
    access_token_secret=os.environ["JWT_SECRET"],   # still used for refresh-token lookup
    id_provider=IdProviderConfig(
        enabled=True,
        # In production, load from environment / secret manager:
        private_key=os.environ.get("IDP_PRIVATE_KEY"),   # PEM-encoded RSA private key
        issuer="https://auth.myplatform.com",
        token_expiry=2592000,        # 30 days (seconds)
        refresh_token_expiry=7776000,  # 90 days (seconds)
        jwks_path="/.well-known/jwks.json",
    ),
)

configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())
```

The JWKS endpoint is automatically mounted at `{api_prefix}{jwks_path}` (default: `/api/auth/.well-known/jwks.json`).

> **Development tip**: when `private_key` is omitted an ephemeral RSA-2048 keypair is auto-generated at startup with a warning.  All tokens are invalidated on restart — **never use this in production**.

### Generating a keypair

```python
from awesome_python_auth import JwksService

private_key, public_key = JwksService.generate_keypair()
# Store private_key in a secret manager; public_key is derived automatically
```

---

## Resource Server mode

When `resource_server` is configured, the auth middleware validates incoming tokens against a **remote JWKS endpoint** issued by a central IdP.  Login/register routes still work normally.

```python
from awesome_python_auth import AuthConfig, AuthConfigurator
from awesome_python_auth.idp import ResourceServerConfig

config = AuthConfig(
    access_token_secret="...",       # still required
    resource_server=ResourceServerConfig(
        enabled=True,
        jwks_url="https://auth.myplatform.com/api/auth/.well-known/jwks.json",
        issuer="https://auth.myplatform.com",   # optional — tokens with wrong iss are rejected
        jwks_cache_ttl=3600,        # 1 hour cache (seconds)
        jwks_fetch_timeout=5.0,     # seconds
    ),
)

configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())
```

`get_current_user`, `require_auth`, and `require_roles` all switch to JWKS-based RS256 verification automatically when Resource Server mode is active.

---

## Complete Example

```python
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from awesome_python_auth import (
    AuthConfig, AuthConfigurator, CsrfMiddleware, require_auth,
)
from awesome_python_auth.models import AuthUser, InMemoryUserStore

user_store = InMemoryUserStore()

config = AuthConfig(
    api_prefix="/api/auth",
    access_token_secret=os.environ["JWT_SECRET"],
    cookie_secure=False,  # True in production
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token", "X-Auth-Strategy"],
)

app.add_middleware(CsrfMiddleware, api_prefix="/api/auth", cookie_secure=False)

configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())

@app.get("/api/todos")
async def todos(user: AuthUser = Depends(require_auth)):
    return {"todos": [], "user": user.email}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
```

---

## Angular Integration (`ng-awesome-node-auth`)

```typescript
// app.config.ts
import { provideAuth, provideAuthUi } from 'ng-awesome-node-auth';

export const appConfig: ApplicationConfig = {
  providers: [
    provideAuth({ apiPrefix: '/api/auth' }),
    provideAuthUi(),
  ]
};
```

No other changes needed — the Angular library sends cookies + CSRF headers automatically.

---

## Flutter Integration (`awesome-node-auth-flutter`)

```dart
// Native (iOS/Android/Desktop)
final auth = AuthClient(AuthOptions(
  apiPrefix: 'http://your-server/api/auth',
));
await auth.checkSession();

// Login
final result = await auth.login('user@example.com', 'password');
```

The Flutter library uses `X-Auth-Strategy: bearer` on native platforms — the Python library detects this and returns tokens in the response body instead of setting cookies.

---

## License

MIT
