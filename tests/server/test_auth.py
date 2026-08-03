"""Tests for auth endpoints: register, login, me, user listing."""
import sqlite3
import pytest
from starlette.testclient import TestClient

import aivas.server.main as main_mod
from aivas.server.main import app
from aivas.database.schema import create_schema


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = sqlite3.connect(str(tmp_path / "auth_test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    monkeypatch.setattr(main_mod, "_conn", db)
    with TestClient(app) as c:
        monkeypatch.setattr(main_mod, "_conn", db)
        yield c, db


def test_register_and_login(client):
    tc, _ = client
    r = tc.post("/api/auth/register", json={"username": "alice", "password": "secret123"})
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert data["user"]["username"] == "alice"
    # alice is the first user in a fresh DB → auto-promoted to admin
    assert data["user"]["role"] == "admin"


def test_login_returns_token(client):
    tc, _ = client
    tc.post("/api/auth/register", json={"username": "bob", "password": "pass1234"})
    r = tc.post("/api/auth/login", json={"username": "bob", "password": "pass1234"})
    assert r.status_code == 200
    assert "token" in r.json()


def test_login_wrong_password(client):
    tc, _ = client
    tc.post("/api/auth/register", json={"username": "carol", "password": "pass1234"})
    r = tc.post("/api/auth/login", json={"username": "carol", "password": "wrong"})
    assert r.status_code == 401


def test_duplicate_username(client):
    tc, _ = client
    tc.post("/api/auth/register", json={"username": "dave", "password": "pass1234"})
    r = tc.post("/api/auth/register", json={"username": "dave", "password": "otherpass"})
    assert r.status_code == 409


def test_me_requires_token(client):
    tc, _ = client
    r = tc.get("/api/auth/me")
    assert r.status_code == 401


def test_me_returns_user(client):
    tc, _ = client
    reg = tc.post("/api/auth/register", json={"username": "eve", "password": "pass1234"})
    token = reg.json()["token"]
    r = tc.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "eve"


def test_users_list_requires_admin(client):
    tc, db = client
    from aivas.server.auth import register_user
    # Seed an admin first so frank registers as a regular user
    register_user(db, "seed_admin", "adminpass", role="admin")
    reg = tc.post("/api/auth/register", json={"username": "frank", "password": "pass1234"})
    token = reg.json()["token"]
    r = tc.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_users_list_admin_access(client):
    tc, db = client
    from aivas.server.auth import register_user
    register_user(db, "admin_user", "adminpass", role="admin")
    r = tc.post("/api/auth/login", json={"username": "admin_user", "password": "adminpass"})
    token = r.json()["token"]
    r2 = tc.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert any(u["username"] == "admin_user" for u in r2.json())


def test_short_password_rejected(client):
    tc, _ = client
    r = tc.post("/api/auth/register", json={"username": "grace", "password": "abc"})
    assert r.status_code == 400


def test_first_user_becomes_admin(client):
    tc, _ = client
    r = tc.post("/api/auth/register", json={"username": "first", "password": "secret123"})
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "admin"


def test_second_user_stays_user(client):
    tc, _ = client
    tc.post("/api/auth/register", json={"username": "first", "password": "secret123"})
    r = tc.post("/api/auth/register", json={"username": "second", "password": "secret123"})
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "user"
