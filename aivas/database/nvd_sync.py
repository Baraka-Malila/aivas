import sqlite3
import time
from datetime import datetime, timezone

import requests

from aivas.database.nvd_ingest import parse_cve_data, insert_cve

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    delay = 0.06 if api_key else 0.6
    params: dict = {"resultsPerPage": 2000, "startIndex": 0}
    if last_sync:
        params["lastModStartDate"] = last_sync
        params["lastModEndDate"] = now

    total_inserted = 0
    total_results = None

    while True:
        response = requests.get(
            NVD_API_URL, params=params, headers=headers, timeout=30
        )
        response.raise_for_status()
        data = response.json()

        if total_results is None:
            total_results = data.get("totalResults", 0)

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            record = parse_cve_data(cve_data)
            if record:
                insert_cve(conn, record)
                total_inserted += 1

        params["startIndex"] += len(vulnerabilities)

        if progress_callback:
            progress_callback(params["startIndex"], total_results)

        if params["startIndex"] >= total_results:
            break

        time.sleep(delay)

    set_last_sync(conn, now)
    return total_inserted
