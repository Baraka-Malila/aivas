import sqlite3
import pytest
import aivas.server.main as _server
from aivas.database.schema import create_schema
from fastapi.testclient import TestClient


@pytest.fixture
def test_conn(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def client(test_conn, monkeypatch):
    # Set _conn before lifespan runs so lifespan skips DB init
    monkeypatch.setattr(_server, "_conn", test_conn)
    with TestClient(_server.app, raise_server_exceptions=True) as c:
        # Re-apply after lifespan in case it overwrote
        monkeypatch.setattr(_server, "_conn", test_conn)
        yield c
