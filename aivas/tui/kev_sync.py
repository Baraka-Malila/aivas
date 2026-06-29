"""KEV auto-sync helpers: staleness check and background downloader."""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Callable


def _kev_needs_sync(conn: sqlite3.Connection) -> bool:
    """Return True if KEV has never been synced or was synced >7 days ago."""
    row = conn.execute(
        "SELECT value FROM sync_meta WHERE key = 'kev_last_updated'"
    ).fetchone()
    if not row:
        return True
    try:
        last = datetime.fromisoformat(row["value"] if isinstance(row, sqlite3.Row) else row[0])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last) > timedelta(days=7)
    except ValueError:
        return True


async def run_kev_background(conn: sqlite3.Connection,
                              tui_print: Callable[[str], None]) -> None:
    """Download and apply KEV feed; silently skip if offline."""
    from aivas.database.kev import fetch_kev, mark_kev
    try:
        cve_ids = await asyncio.to_thread(fetch_kev)
        count = mark_kev(conn, cve_ids)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)",
            ("kev_last_updated", now),
        )
        conn.commit()
        tui_print(
            f"[dim]KEV: {count:,} active exploits tracked  "
            f"(synced {datetime.now().strftime('%Y-%m-%d')})[/dim]"
        )
    except Exception:
        pass  # silently skip if offline — no crash, no noise
