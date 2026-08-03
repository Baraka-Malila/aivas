"""Auth helpers — password hashing, JWT issue/verify, FastAPI dependency."""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import HTTPException, Header

_SECRET = os.environ.get("AIVAS_JWT_SECRET", "aivas-dev-secret-change-in-prod")
_ALGORITHM = "HS256"
_TOKEN_TTL_HOURS = 24 * 7  # 1 week


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=_TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def register_user(
    conn: sqlite3.Connection, username: str, password: str, role: str = "user"
) -> dict:
    username = username.strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    existing = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")
    pw_hash = hash_password(password)
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, pw_hash, role),
    )
    conn.commit()
    return {"id": cur.lastrowid, "username": username, "role": role}


def login_user(conn: sqlite3.Connection, username: str, password: str) -> str:
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return create_token(row["id"], row["username"], row["role"])


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """FastAPI dependency — extracts and verifies Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization[7:])


def get_current_user_optional(authorization: Optional[str] = Header(None)) -> dict | None:
    """Like get_current_user but returns None instead of raising 401."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        return decode_token(authorization[7:])
    except HTTPException:
        return None


def require_admin(user: dict) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def list_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]
