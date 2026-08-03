import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

from aivas.database.schema import create_schema
from aivas.server.scheduler import compute_next_run, get_due_schedules


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def _insert(conn, target="192.168.1.1", interval="daily", enabled=1, next_run="2025-01-01T00:00:00+00:00"):
    conn.execute(
        "INSERT INTO scheduled_scans (label, target, interval, enabled, next_run) VALUES (?, ?, ?, ?, ?)",
        (f"Test {target}", target, interval, enabled, next_run),
    )
    conn.commit()


# ── compute_next_run ─────────────────────────────────────────────────────────

def test_hourly():
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_next_run("hourly", now) == datetime(2025, 1, 1, 13, 0, tzinfo=timezone.utc)


def test_daily():
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_next_run("daily", now) == datetime(2025, 1, 2, 12, 0, tzinfo=timezone.utc)


def test_weekly():
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_next_run("weekly", now) == datetime(2025, 1, 8, 12, 0, tzinfo=timezone.utc)


def test_unknown_interval_defaults_to_daily():
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_next_run("monthly", now) == now + timedelta(days=1)


# ── get_due_schedules ─────────────────────────────────────────────────────────

def test_due_schedule_returned(conn):
    _insert(conn, next_run="2025-01-01T00:00:00+00:00")
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    due = get_due_schedules(conn, now)
    assert len(due) == 1
    assert due[0]["target"] == "192.168.1.1"


def test_future_schedule_skipped(conn):
    _insert(conn, next_run="2099-01-01T00:00:00+00:00")
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    assert get_due_schedules(conn, now) == []


def test_disabled_schedule_skipped(conn):
    _insert(conn, enabled=0, next_run="2025-01-01T00:00:00+00:00")
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    assert get_due_schedules(conn, now) == []


def test_exact_boundary_is_due(conn):
    ts = "2025-06-01T00:00:00+00:00"
    _insert(conn, next_run=ts)
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    assert len(get_due_schedules(conn, now)) == 1


def test_multiple_due(conn):
    _insert(conn, target="10.0.0.1", next_run="2025-01-01T00:00:00+00:00")
    _insert(conn, target="10.0.0.2", next_run="2025-01-01T00:00:00+00:00")
    _insert(conn, target="10.0.0.3", next_run="2099-01-01T00:00:00+00:00")
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    due = get_due_schedules(conn, now)
    assert len(due) == 2
    targets = {r["target"] for r in due}
    assert targets == {"10.0.0.1", "10.0.0.2"}


def test_due_result_has_required_keys(conn):
    _insert(conn, next_run="2025-01-01T00:00:00+00:00")
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    row = get_due_schedules(conn, now)[0]
    assert "id" in row
    assert "target" in row
    assert "interval" in row
    assert "remote_target_id" in row
