import sqlite3
from datetime import datetime, timezone

import nvdlib

from aivas.database.nvd_ingest import parse_cve_data, insert_cve


def get_last_sync(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT value FROM sync_meta WHERE key = 'last_sync'"
    ).fetchone()
    return row["value"] if row else None


def set_last_sync(conn: sqlite3.Connection, ts: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_sync', ?)",
        (ts,),
    )
    conn.commit()


def sync_from_api(
    conn: sqlite3.Connection,
    api_key: str | None = None,
    progress_callback=None,
) -> int:
    last_sync = get_last_sync(conn)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    kwargs: dict = {}
    if last_sync:
        kwargs["lastModStartDate"] = last_sync
        kwargs["lastModEndDate"] = now
    if api_key:
        kwargs["key"] = api_key
        kwargs["delay"] = 0.06
    else:
        kwargs["delay"] = 0.6

    results = nvdlib.searchCVE(**kwargs)

    total_inserted = 0
    total = len(results)
    for i, cve in enumerate(results):
        record = parse_cve_data(vars(cve))
        if record:
            insert_cve(conn, record)
            total_inserted += 1
        if progress_callback:
            progress_callback(i + 1, total)

    # advance the window even if 0 CVEs parsed — avoids re-fetching same window
    set_last_sync(conn, now)
    return total_inserted
