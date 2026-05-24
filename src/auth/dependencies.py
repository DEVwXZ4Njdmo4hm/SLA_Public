#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         dependencies.py
Description:  FastAPI dependency injection for JWT and API Key authentication.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
from typing import Callable, Optional, TYPE_CHECKING

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader

from .models import Role, User
from .tokens import decode_jwt

if TYPE_CHECKING:
    from .database import UserDB

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Module-level reference set by ``init_auth_dependencies``.
_user_db: Optional["UserDB"] = None
_jwt_secret: str = ""


def init_auth_dependencies(user_db: "UserDB", jwt_secret: str) -> None:
    """Must be called once at startup to wire the DB and secret."""
    global _user_db, _jwt_secret
    _user_db = user_db
    _jwt_secret = jwt_secret


async def get_current_user(
    request: Request,
    token: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    api_key: Optional[str] = Depends(_api_key_header),
) -> User:
    """Resolve the current authenticated user from JWT or API Key."""
    if _user_db is None:
        raise HTTPException(status_code=503, detail="Auth subsystem not initialised.")

    # 1) Try JWT bearer token
    if token is not None:
        payload = decode_jwt(token.credentials, _jwt_secret)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token.")
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token missing subject.")
        user = _user_db.get_user_by_id(int(user_id))
        if user is None:
            raise HTTPException(status_code=401, detail="User not found.")
        return user

    # 2) Try API key
    if api_key is not None:
        user = _user_db.verify_api_key(api_key)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key.")
        return user

    raise HTTPException(status_code=401, detail="Missing credentials.")


def require_role(*roles: Role) -> Callable:
    """Return a FastAPI dependency that enforces the caller has one of *roles*."""
    async def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {[r.value for r in roles]}",
            )
        return user
    return _checker
