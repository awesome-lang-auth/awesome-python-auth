"""Admin router for awesome-python-auth.

Provides a ``build_admin_router()`` factory that returns a FastAPI ``APIRouter``
exposing a protected admin REST API and a bundled SPA for managing users, sessions,
roles, tenants, API keys, webhooks, and application settings.

Access control
--------------
Three access policies mirror ``awesome-node-auth``'s ``AdminAccessPolicy``:

- ``"is-admin-flag"`` *(default)* — only users with ``AuthUser.is_admin == True``.
- ``"first-user"`` — only the user with the lexicographically smallest ID.
- ``"open"`` — no restriction; useful behind a VPN / IP allow-list.

Usage::

    from awesome_python_auth import build_admin_router, AuthConfig

    app.include_router(
        build_admin_router(
            config=config,
            user_store=user_store,
            session_store=None,       # optional
            rbac_store=None,          # optional
            tenant_store=None,        # optional
            settings_store=None,      # optional
            access_policy="is-admin-flag",
        ),
        prefix="/admin",
    )
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .dependencies import get_current_user
from .events import AuthEventNames
from .models import AuthUser, SessionInfo, SettingsStore, StoredUser, UserStore
from .router import _request_event_context

_ASSETS_DIR = Path(__file__).parent / "ui_assets"

# ---------------------------------------------------------------------------
# Access-policy type
# ---------------------------------------------------------------------------

AdminAccessPolicy = str  # "is-admin-flag" | "first-user" | "open"


# ---------------------------------------------------------------------------
# Guard helper
# ---------------------------------------------------------------------------

async def _check_admin(
    user: AuthUser | None,
    user_store: UserStore,
    access_policy: AdminAccessPolicy,
) -> AuthUser:
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if access_policy == "open":
        return user

    if access_policy == "is-admin-flag":
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        return user

    if access_policy == "first-user":
        # The first user is the one with the smallest ID lexicographically
        all_users = await user_store.list_all_users(offset=0, limit=1)
        if not all_users:
            raise HTTPException(status_code=403, detail="No users found")
        first = min((u.id for u in all_users), default=None)
        if user.sub != first:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        return user

    raise HTTPException(status_code=403, detail="Unknown access policy")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_admin_router(
    *,
    config: Any,
    user_store: UserStore,
    session_store: Any = None,
    rbac_store: Any = None,
    tenant_store: Any = None,
    settings_store: SettingsStore | None = None,
    linked_accounts_store: Any = None,
    api_key_store: Any = None,
    webhook_store: Any = None,
    access_policy: AdminAccessPolicy = "is-admin-flag",
    event_bus: Any = None,
) -> APIRouter:
    """Return a configured admin :class:`fastapi.APIRouter`.

    Parameters
    ----------
    config:
        The :class:`~awesome_python_auth.config.AuthConfig` for the application.
    user_store:
        The :class:`~awesome_python_auth.models.UserStore` implementation.
    session_store:
        Optional — enables the Sessions tab.
    rbac_store:
        Optional :class:`~awesome_python_auth.rebac.RolesPermissionsStore` —
        enables the Roles & Permissions tab and user-role assignment endpoints.
    tenant_store:
        Optional :class:`~awesome_python_auth.tenants.TenantStore` —
        enables the Tenants tab.
    settings_store:
        Optional :class:`~awesome_python_auth.models.SettingsStore` —
        enables the Settings tab.
    linked_accounts_store:
        Optional :class:`~awesome_python_auth.linked_accounts.LinkedAccountsStore` —
        enables linked-accounts display per user.
    api_key_store:
        Optional — enables the API Keys tab.
    webhook_store:
        Optional — enables the Webhooks tab.
    access_policy:
        One of ``"is-admin-flag"`` (default), ``"first-user"``, or ``"open"``.
    event_bus:
        Optional :class:`~awesome_python_auth.events.AuthEventBus` instance
        for auto-publishing admin and role lifecycle events.
    """
    router = APIRouter()
    effective_event_bus = event_bus if event_bus is not None else getattr(config, "event_bus", None)

    # ------------------------------------------------------------------
    # Admin guard dependency
    # ------------------------------------------------------------------

    async def admin_user(
        user: AuthUser | None = Depends(get_current_user),
        request: Request = None,  # type: ignore[assignment]
    ) -> AuthUser:
        return await _check_admin(user, user_store, access_policy)

    # ------------------------------------------------------------------
    # Serve admin HTML SPA
    # ------------------------------------------------------------------

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    @router.get("", response_class=HTMLResponse, include_in_schema=False)
    async def admin_ui() -> HTMLResponse:
        html_path = _ASSETS_DIR / "admin.html"
        if not html_path.exists():
            return HTMLResponse("<h1>Admin UI not found</h1>", status_code=404)
        return HTMLResponse(html_path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Health / ping
    # ------------------------------------------------------------------

    @router.get("/api/ping")
    async def ping(admin: AuthUser = Depends(admin_user)) -> dict:
        return {"ok": True, "userId": admin.sub, "email": admin.email}

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    @router.get("/api/users")
    async def list_users(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        users = await user_store.list_all_users(offset=offset, limit=limit)
        total = await user_store.count_users()
        return {
            "users": [_user_to_dict(u) for u in users],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @router.get("/api/users/{user_id}")
    async def get_user(
        user_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        user = await user_store.get_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return _user_to_dict(user)

    @router.delete("/api/users/{user_id}", status_code=204)
    async def delete_user(
        user_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        user = await user_store.get_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        await user_store.delete_sessions_for_user(user_id)
        await user_store.delete(user_id)
        return Response(status_code=204)

    @router.patch("/api/users/{user_id}")
    async def update_user(
        user_id: str,
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        user = await user_store.get_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        allowed = {"first_name", "last_name", "name", "is_admin", "role", "is_email_verified", "metadata"}
        for key, value in body.items():
            snake = _camel_to_snake(key)
            if snake in allowed:
                setattr(user, snake, value)
        if user.first_name is not None or user.last_name is not None:
            user.name = f"{user.first_name or ''} {user.last_name or ''}".strip() or None
        await user_store.update(user)
        return _user_to_dict(user)

    # ------------------------------------------------------------------
    # Users — linked accounts
    # ------------------------------------------------------------------

    @router.get("/api/users/{user_id}/linked-accounts")
    async def get_user_linked_accounts(
        user_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if linked_accounts_store is None:
            return {"linkedAccounts": []}
        accounts = await linked_accounts_store.get_by_user(user_id)
        return {"linkedAccounts": [a.to_api_dict() for a in accounts]}

    # ------------------------------------------------------------------
    # Users — roles (via RBAC store)
    # ------------------------------------------------------------------

    @router.get("/api/users/{user_id}/roles")
    async def get_user_roles(
        user_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if rbac_store is None:
            return {"roles": []}
        roles = await rbac_store.get_roles_for_user(user_id)
        return {"roles": roles}

    @router.post("/api/users/{user_id}/roles", status_code=201)
    async def add_user_role(
        user_id: str,
        body: dict,
        request: Request = None,  # type: ignore[assignment]
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        role = body.get("role", "")
        tenant_id = body.get("tenantId") or body.get("tenant_id")
        if not role:
            raise HTTPException(status_code=400, detail="role is required")
        await rbac_store.add_role_to_user(user_id, role, tenant_id=tenant_id)
        if effective_event_bus is not None:
            ctx = _request_event_context(request)
            data: dict[str, Any] = {"role": role}
            if access_policy != "open" and admin:
                data["actorId"] = admin.sub
            ev_payload: dict[str, Any] = {
                **ctx,
                "userId": user_id,
                "data": data,
            }
            if tenant_id:
                ev_payload["tenantId"] = tenant_id
            try:
                effective_event_bus.publish(AuthEventNames.ROLE_ASSIGNED, ev_payload)
            except Exception:
                pass
        return {"success": True}

    @router.delete("/api/users/{user_id}/roles/{role}", status_code=204)
    async def remove_user_role(
        user_id: str,
        role: str,
        request: Request = None,  # type: ignore[assignment]
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        await rbac_store.remove_role_from_user(user_id, role)
        if effective_event_bus is not None:
            ctx = _request_event_context(request)
            data: dict[str, Any] = {"role": role}
            if access_policy != "open" and admin:
                data["actorId"] = admin.sub
            try:
                effective_event_bus.publish(
                    AuthEventNames.ROLE_REVOKED,
                    {
                        **ctx,
                        "userId": user_id,
                        "data": data,
                    },
                )
            except Exception:
                pass
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Roles & Permissions
    # ------------------------------------------------------------------

    @router.get("/api/roles")
    async def list_roles(admin: AuthUser = Depends(admin_user)) -> dict:
        if rbac_store is None:
            return {"roles": []}
        role_names = await rbac_store.get_all_roles()
        roles = []
        for name in role_names:
            perms = await rbac_store.get_permissions_for_role(name)
            roles.append({"name": name, "permissions": perms})
        return {"roles": roles}

    @router.post("/api/roles", status_code=201)
    async def create_role(
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        name = body.get("name", "")
        permissions = body.get("permissions", [])
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        await rbac_store.create_role(name, permissions)
        return {"success": True, "name": name}

    @router.delete("/api/roles/{role_name}", status_code=204)
    async def delete_role(
        role_name: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        await rbac_store.delete_role(role_name)
        return Response(status_code=204)

    @router.post("/api/roles/{role_name}/permissions")
    async def add_permission_to_role(
        role_name: str,
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        permission = body.get("permission", "")
        if not permission:
            raise HTTPException(status_code=400, detail="permission is required")
        await rbac_store.add_permission_to_role(role_name, permission)
        return {"success": True}

    @router.delete("/api/roles/{role_name}/permissions/{permission}", status_code=204)
    async def remove_permission_from_role(
        role_name: str,
        permission: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if rbac_store is None:
            raise HTTPException(status_code=501, detail="RBAC store not configured")
        await rbac_store.remove_permission_from_role(role_name, permission)
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    @router.get("/api/sessions")
    async def list_sessions(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        # Use dedicated session_store if provided, otherwise fall back to user_store
        _store = session_store or user_store
        sessions = await _store.list_all_sessions(offset=offset, limit=limit)
        total = await _store.count_active_sessions()
        return {
            "sessions": [_session_to_dict(s) for s in sessions],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @router.delete("/api/sessions/{handle}", status_code=204)
    async def revoke_session(
        handle: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        _store = session_store or user_store
        await _store.delete_session(handle)
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    @router.get("/api/tenants")
    async def list_tenants(admin: AuthUser = Depends(admin_user)) -> dict:
        if tenant_store is None:
            return {"tenants": []}
        tenants = await tenant_store.get_all_tenants()
        return {"tenants": [t.to_api_dict() for t in tenants]}

    @router.post("/api/tenants", status_code=201)
    async def create_tenant(
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if tenant_store is None:
            raise HTTPException(status_code=501, detail="Tenant store not configured")
        tenant = await tenant_store.create_tenant(body)
        return tenant.to_api_dict()

    @router.patch("/api/tenants/{tenant_id}")
    async def update_tenant(
        tenant_id: str,
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if tenant_store is None:
            raise HTTPException(status_code=501, detail="Tenant store not configured")
        updated = await tenant_store.update_tenant(tenant_id, body)
        if updated is None:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return updated.to_api_dict()

    @router.delete("/api/tenants/{tenant_id}", status_code=204)
    async def delete_tenant(
        tenant_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if tenant_store is None:
            raise HTTPException(status_code=501, detail="Tenant store not configured")
        await tenant_store.delete_tenant(tenant_id)
        return Response(status_code=204)

    @router.get("/api/tenants/{tenant_id}/users")
    async def get_tenant_users(
        tenant_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if tenant_store is None:
            return {"users": []}
        user_ids = await tenant_store.get_users_for_tenant(tenant_id)
        return {"users": user_ids}

    @router.post("/api/tenants/{tenant_id}/users", status_code=201)
    async def add_user_to_tenant(
        tenant_id: str,
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if tenant_store is None:
            raise HTTPException(status_code=501, detail="Tenant store not configured")
        user_id = body.get("userId", "")
        if not user_id:
            raise HTTPException(status_code=400, detail="userId is required")
        await tenant_store.associate_user_with_tenant(user_id, tenant_id)
        return {"success": True}

    @router.delete("/api/tenants/{tenant_id}/users/{user_id}", status_code=204)
    async def remove_user_from_tenant(
        tenant_id: str,
        user_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if tenant_store is None:
            raise HTTPException(status_code=501, detail="Tenant store not configured")
        await tenant_store.disassociate_user_from_tenant(user_id, tenant_id)
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    @router.get("/api/settings")
    async def get_settings(admin: AuthUser = Depends(admin_user)) -> dict:
        if settings_store is None:
            return {}
        all_keys = [
            "siteName", "logoUrl", "primaryColor", "accentColor",
            "backgroundImageUrl", "loginRedirectUrl", "requireEmailVerification",
            "require2FA", "allowRegistration", "allowedAuthMethods",
        ]
        result: dict[str, Any] = {}
        for key in all_keys:
            val = await settings_store.get(key)
            if val is not None:
                result[key] = val
        return result

    @router.put("/api/settings")
    async def update_settings(
        body: dict,
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if settings_store is None:
            raise HTTPException(status_code=501, detail="Settings store not configured")
        for key, value in body.items():
            await settings_store.set(key, value)
        return {"success": True}

    # ------------------------------------------------------------------
    # API Keys (admin view — list all, hard delete)
    # ------------------------------------------------------------------

    @router.get("/api/api-keys")
    async def list_api_keys(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if api_key_store is None:
            return {"apiKeys": [], "total": 0}
        try:
            keys = await api_key_store.list_all(offset=offset, limit=limit)
        except AttributeError:
            # list_all is optional in ApiKeyStore
            keys = []
        return {"apiKeys": [k.to_api_dict() if hasattr(k, "to_api_dict") else k for k in keys]}

    @router.delete("/api/api-keys/{key_id}", status_code=204)
    async def hard_delete_api_key(
        key_id: str,
        admin: AuthUser = Depends(admin_user),
    ) -> Response:
        if api_key_store is None:
            raise HTTPException(status_code=501, detail="API key store not configured")
        try:
            await api_key_store.delete(key_id)
        except AttributeError:
            await api_key_store.revoke(key_id)
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Webhooks (admin view)
    # ------------------------------------------------------------------

    @router.get("/api/webhooks")
    async def list_webhooks(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        admin: AuthUser = Depends(admin_user),
    ) -> dict:
        if webhook_store is None:
            return {"webhooks": []}
        try:
            hooks = await webhook_store.list_all(offset=offset, limit=limit)
        except AttributeError:
            hooks = []
        return {"webhooks": hooks}

    return router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_to_dict(user: StoredUser) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "name": user.name,
        "role": user.role,
        "roles": user.roles or [],
        "permissions": user.permissions or [],
        "isAdmin": user.is_admin,
        "isEmailVerified": user.is_email_verified,
        "isTotpEnabled": user.is_totp_enabled,
        "loginProvider": user.login_provider,
        "phoneNumber": user.phone_number,
        "lastLogin": user.last_login.isoformat() if user.last_login else None,
        "metadata": user.metadata,
        "tenantId": user.tenant_id,
    }


def _session_to_dict(session: Any) -> dict[str, Any]:
    from .models import StoredSession
    return {
        "sessionHandle": session.handle,
        "userId": session.user_id,
        "userAgent": session.user_agent,
        "ipAddress": session.ip_address,
        "createdAt": session.created_at.isoformat() if session.created_at else None,
        "lastActiveAt": session.last_active_at.isoformat() if session.last_active_at else None,
    }


def _camel_to_snake(name: str) -> str:
    import re
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
