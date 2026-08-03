"""Background asyncio scheduler for recurring scans."""
from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

_log = logging.getLogger("aivas.scheduler")

INTERVALS: dict[str, timedelta] = {
    "hourly": timedelta(hours=1),
    "daily":  timedelta(days=1),
    "weekly": timedelta(weeks=1),
}


def compute_next_run(interval: str, from_dt: datetime) -> datetime:
    """Return the next scheduled time after from_dt for the given interval name."""
    return from_dt + INTERVALS.get(interval, timedelta(days=1))


def get_due_schedules(conn: sqlite3.Connection, now: datetime) -> list[dict]:
    """Return enabled schedules whose next_run is at or before now."""
    rows = conn.execute(
        "SELECT id, label, target, remote_target_id, interval "
        "FROM scheduled_scans WHERE enabled = 1 AND next_run <= ?",
        (now.isoformat(),),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_creds(conn: sqlite3.Connection, remote_target_id: int | None) -> dict | None:
    if remote_target_id is None:
        return None
    row = conn.execute(
        "SELECT method, username, password, port, key_path "
        "FROM remote_targets WHERE id = ?",
        (remote_target_id,),
    ).fetchone()
    return dict(row) if row else None


def _mark_ran(conn: sqlite3.Connection, schedule_id: int, interval: str, ran_at: datetime) -> None:
    next_run = compute_next_run(interval, ran_at)
    conn.execute(
        "UPDATE scheduled_scans SET last_run = ?, next_run = ? WHERE id = ?",
        (ran_at.isoformat(), next_run.isoformat(), schedule_id),
    )
    conn.commit()


async def _run_one(conn: sqlite3.Connection, row: dict) -> None:
    """Consume a full scan for one scheduled entry and record completion."""
    from aivas.server.scan_worker import run_scan

    schedule_id = row["id"]
    target = row["target"]
    creds = _get_creds(conn, row.get("remote_target_id"))
    ran_at = datetime.now(timezone.utc)

    _log.info("Scheduled scan starting: %s (schedule #%d)", target, schedule_id)
    try:
        async for ev in run_scan(conn, target, level=2, creds=creds):
            if ev.get("type") == "done":
                _log.info(
                    "Scheduled scan done: %s — scan_id=%s grade=%s",
                    target, ev.get("scan_id"), ev.get("grade"),
                )
            elif ev.get("type") == "error":
                _log.error("Scheduled scan error [%s]: %s", target, ev.get("text"))
    except Exception as exc:
        _log.error("Scheduled scan exception [%s]: %s", target, exc)
    finally:
        _mark_ran(conn, schedule_id, row["interval"], ran_at)


async def scheduler_loop(conn: sqlite3.Connection) -> None:
    """Tick every 60 s; dispatch asyncio tasks for any due scheduled scans."""
    _log.info("Scheduler started")
    while True:
        try:
            await asyncio.sleep(60)
            now = datetime.now(timezone.utc)
            for row in get_due_schedules(conn, now):
                asyncio.create_task(_run_one(conn, row))
        except asyncio.CancelledError:
            _log.info("Scheduler stopped")
            raise
        except Exception as exc:
            _log.error("Scheduler tick error: %s", exc)
