import sqlite3
from fastapi.testclient import TestClient
import pytest
from aivas.database.schema import create_schema


@pytest.fixture
def client(tmp_path):
    import aivas.server.main as srv
    db = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    srv._conn = db
    srv._pending = {}
    return TestClient(srv.app)


def test_post_scan_returns_scan_key(client):
    resp = client.post("/api/scan", json={"target": "10.0.0.1", "level": 1})
    assert resp.status_code == 200
    assert "scan_key" in resp.json()


def test_delete_scan(client):
    import aivas.server.main as srv
    conn = srv._conn
    conn.execute(
        "INSERT INTO scans (target, started_at, finished_at, host_count, finding_count, "
        "risk_score, grade) VALUES (?,?,?,?,?,?,?)",
        ("192.168.1.1", "2026-01-01", "2026-01-01", 1, 0, 0, "Grade A"),
    )
    conn.commit()
    scan_id = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()["id"]
    resp = client.delete(f"/api/scan/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == scan_id
    assert not conn.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
