"""FastAPI router — scheduled scan CRUD endpoints."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from aivas.server.scheduler import compute_next_run

router = APIRouter()
_conn: sqlite3.Connection | None = None


def set_conn(conn: sqlite3.Connection) -> None:
    global _conn
    _conn = conn


_SELECT = (
    "SELECT id, label, target, remote_target_id, interval, "
    "enabled, last_run, next_run, created_at FROM scheduled_scans"
)


class ScheduleRequest(BaseModel):
    label: str
    target: str
    interval: str = "daily"
    remote_target_id: int | None = None
    enabled: bool = True


class SchedulePatch(BaseModel):
    enabled: bool


@router.get("/api/schedules")
async def list_schedules():
    rows = _conn.execute(f"{_SELECT} ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


@router.post("/api/schedules")
async def create_schedule(body: ScheduleRequest):
    now = datetime.now(timezone.utc)
    next_run = compute_next_run(body.interval, now)
    cur = _conn.execute(
        "INSERT INTO scheduled_scans (label, target, remote_target_id, interval, enabled, next_run) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            body.label, body.target, body.remote_target_id,
            body.interval, 1 if body.enabled else 0,
            next_run.isoformat(),
        ),
    )
    _conn.commit()
    row = _conn.execute(f"{_SELECT} WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


@router.patch("/api/schedules/{schedule_id}")
async def toggle_schedule(schedule_id: int, body: SchedulePatch):
    if not _conn.execute("SELECT 1 FROM scheduled_scans WHERE id = ?", (schedule_id,)).fetchone():
        raise HTTPException(status_code=404, detail="Schedule not found")
    _conn.execute(
        "UPDATE scheduled_scans SET enabled = ? WHERE id = ?",
        (1 if body.enabled else 0, schedule_id),
    )
    _conn.commit()
    row = _conn.execute(f"{_SELECT} WHERE id = ?", (schedule_id,)).fetchone()
    return dict(row)


@router.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int):
    changes = _conn.execute(
        "DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,)
    ).rowcount
    _conn.commit()
    if not changes:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"deleted": schedule_id}
