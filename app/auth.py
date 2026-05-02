from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import HTTPException, Request, status


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


USERS = {
    "admin": {"password_hash": _hash("Admin123!"), "role": "admin", "display_name": "系统管理员"},
    "operator": {"password_hash": _hash("Operator123!"), "role": "operator", "display_name": "调度操作员"},
    "auditor": {"password_hash": _hash("Auditor123!"), "role": "auditor", "display_name": "安全审计员"},
}


@dataclass
class SessionUser:
    username: str
    role: str
    display_name: str
    expires_at: float


class SessionStore:
    def __init__(self) -> None:
        self.sessions: Dict[str, SessionUser] = {}

    def create(self, username: str) -> str:
        info = USERS[username]
        token = secrets.token_urlsafe(24)
        self.sessions[token] = SessionUser(
            username=username,
            role=info["role"],
            display_name=info["display_name"],
            expires_at=time.time() + 60 * 60 * 8,
        )
        return token

    def get(self, token: str | None) -> Optional[SessionUser]:
        if not token:
            return None
        user = self.sessions.get(token)
        if not user:
            return None
        if user.expires_at < time.time():
            self.sessions.pop(token, None)
            return None
        return user

    def destroy(self, token: str | None) -> None:
        if token:
            self.sessions.pop(token, None)


def authenticate(username: str, password: str) -> Optional[str]:
    user = USERS.get(username)
    if not user:
        return None
    if _hash(password) != user["password_hash"]:
        return None
    return username


def require_user(request: Request, session_token: str | None = None) -> SessionUser:
    if session_token is None:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            session_token = auth_header.split(" ", 1)[1].strip()
    if session_token is None:
        session_token = request.cookies.get("session_token")
    store: SessionStore = request.app.state.sessions
    user = store.get(session_token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not_authenticated")
    return user


def require_roles(request: Request, allowed_roles: set[str], session_token: str | None = None) -> SessionUser:
    if session_token is None:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            session_token = auth_header.split(" ", 1)[1].strip()
    if session_token is None:
        session_token = request.cookies.get("session_token")
    user = require_user(request, session_token)
    if user.role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    return user
