"""Auth event bus for awesome-python-auth.

Mirrors the ``AuthEventBus`` and ``AuthEventNames`` from awesome-node-auth.

The bus is a lightweight publish/subscribe system.  Both sync and async
handlers are supported.  Handlers registered on the wildcard topic ``'*'``
receive every event.

Usage::

    from awesome_python_auth.events import AuthEventBus, AuthEventNames

    bus = AuthEventBus()

    # Sync handler
    def on_login(payload):
        print("Login:", payload["userId"])

    bus.on_event(AuthEventNames.AUTH_LOGIN_SUCCESS, on_login)

    # Async handler
    async def async_on_login(payload):
        await db.log(payload["event"], payload["userId"])

    bus.on_event(AuthEventNames.AUTH_LOGIN_SUCCESS, async_on_login)

    # Wildcard — receives every event
    bus.on_event("*", lambda p: print(p["event"]))

    # Publish
    bus.publish(AuthEventNames.AUTH_LOGIN_SUCCESS, {"userId": "123"})

    # Unsubscribe
    bus.off_event(AuthEventNames.AUTH_LOGIN_SUCCESS, on_login)
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payload type alias (dict so it is JSON-compatible)
# ---------------------------------------------------------------------------

AuthEventPayload = dict[str, Any]
"""A dict with at least ``"event"`` (str) and ``"timestamp"`` (ISO-8601 str).

Common keys:
  event, timestamp, data, userId, tenantId, sessionId, correlationId, ip, userAgent
"""


# ---------------------------------------------------------------------------
# Standard event name constants
# ---------------------------------------------------------------------------


class AuthEventNames:
    """Standard identity event names.

    Follows the ``domain.resource.action`` convention used by awesome-node-auth.
    """

    # ---- User ----------------------------------------------------------------
    USER_CREATED = "identity.user.created"
    USER_DELETED = "identity.user.deleted"
    USER_EMAIL_VERIFIED = "identity.user.email.verified"
    USER_EMAIL_CHANGED = "identity.user.email.changed"
    USER_PASSWORD_CHANGED = "identity.user.password.changed"
    USER_2FA_ENABLED = "identity.user.2fa.enabled"
    USER_2FA_DISABLED = "identity.user.2fa.disabled"
    USER_LINKED = "identity.user.linked"
    USER_UNLINKED = "identity.user.unlinked"

    # ---- Session -------------------------------------------------------------
    SESSION_CREATED = "identity.session.created"
    SESSION_REVOKED = "identity.session.revoked"
    SESSION_EXPIRED = "identity.session.expired"
    SESSION_ROTATED = "identity.session.rotated"

    # ---- Authentication ------------------------------------------------------
    AUTH_LOGIN_SUCCESS = "identity.auth.login.success"
    AUTH_LOGIN_FAILED = "identity.auth.login.failed"
    AUTH_LOGOUT = "identity.auth.logout"
    AUTH_OAUTH_SUCCESS = "identity.auth.oauth.success"
    AUTH_OAUTH_CONFLICT = "identity.auth.oauth.conflict"

    # ---- Tenant --------------------------------------------------------------
    TENANT_CREATED = "identity.tenant.created"
    TENANT_DELETED = "identity.tenant.deleted"
    TENANT_USER_ADDED = "identity.tenant.user.added"
    TENANT_USER_REMOVED = "identity.tenant.user.removed"

    # ---- Authorization -------------------------------------------------------
    ROLE_ASSIGNED = "identity.role.assigned"
    ROLE_REVOKED = "identity.role.revoked"
    PERMISSION_GRANTED = "identity.permission.granted"
    PERMISSION_REVOKED = "identity.permission.revoked"


# ---------------------------------------------------------------------------
# AuthEventBus
# ---------------------------------------------------------------------------


class AuthEventBus:
    """Central event bus for all identity-related events.

    Acts as the backbone of the event-driven tools system.  Auth core
    components emit standardised events here; downstream handlers (telemetry,
    SSE, webhooks, analytics) subscribe and react without coupling to each
    other.

    The bus is intentionally lightweight — there is zero runtime overhead when
    no listeners are registered.

    Both sync and async handlers are supported.  Async handlers are scheduled
    on the current event loop via :func:`asyncio.ensure_future`.

    The wildcard topic ``'*'`` receives every published event.
    """

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable]] = defaultdict(list)

    # ---- Subscribe -----------------------------------------------------------

    def on_event(self, event_name: str, handler: Callable[[AuthEventPayload], Any]) -> "AuthEventBus":
        """Subscribe *handler* to *event_name*.

        :param event_name: Exact event name or ``'*'`` for all events.
        :param handler:    Sync or async callable receiving the full payload.
        :returns: ``self`` for chaining.
        """
        self._listeners[event_name].append(handler)
        return self

    def off_event(self, event_name: str, handler: Callable[[AuthEventPayload], Any]) -> "AuthEventBus":
        """Unsubscribe *handler* from *event_name*.

        :returns: ``self`` for chaining.
        """
        try:
            self._listeners[event_name].remove(handler)
        except ValueError:
            pass
        return self

    # ---- Publish -------------------------------------------------------------

    def publish(
        self,
        event_name: str,
        payload: dict[str, Any],
    ) -> None:
        """Publish *payload* under *event_name*.

        ``event`` and ``timestamp`` fields are injected automatically if
        not already present.

        Handlers are called **synchronously** for sync callables and scheduled
        as fire-and-forget tasks for async callables.  A failure in any handler
        is logged and silently swallowed so that a bad listener never disrupts
        the auth flow.

        :param event_name: Event name (e.g. ``AuthEventNames.AUTH_LOGIN_SUCCESS``).
        :param payload:    Dict of metadata to attach to the event.
        """
        full: AuthEventPayload = {
            **payload,
            "event": event_name,
            "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        }

        for name in (event_name, "*"):
            for handler in list(self._listeners.get(name, [])):
                self._call(handler, full)

    # ---- Helpers -------------------------------------------------------------

    def _call(self, handler: Callable, payload: AuthEventPayload) -> None:
        try:
            if inspect.iscoroutinefunction(handler):
                loop = None
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    pass
                if loop and loop.is_running():
                    asyncio.ensure_future(handler(payload))
                else:
                    asyncio.run(handler(payload))
            else:
                handler(payload)
        except Exception:
            logger.exception("AuthEventBus: error in handler %r for event %r", handler, payload.get("event"))
