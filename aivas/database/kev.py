import json
import urllib.request
from datetime import datetime, timezone
from sqlite3 import Connection

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_META_KEY = "kev_last_updated"


def fetch_kev(url: str = KEV_URL) -> list[str]:
    """Download CISA KEV feed and return list of CVE IDs."""
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read())
    return [v["cveID"] for v in data.get("vulnerabilities", [])]


def mark_kev(conn: Connection, cve_ids: list[str]) -> int:
    """Set kev=1 for each CVE ID present in local DB. Returns count marked."""
    marked = 0
    for cve_id in cve_ids:
        cursor = conn.execute("UPDATE cves SET kev = 1 WHERE cve_id = ?", (cve_id,))
        marked += cursor.rowcount
    conn.commit()
    return marked


def get_kev_status(conn: Connection) -> dict:
    """Return count of KEV-flagged CVEs and last sync timestamp."""
    count = conn.execute("SELECT COUNT(*) FROM cves WHERE kev = 1").fetchone()[0]
    row = conn.execute(
        "SELECT value FROM sync_meta WHERE key = ?", (_META_KEY,)
    ).fetchone()
    return {"count": count, "last_updated": row[0] if row else None}


def sync_kev(conn: Connection, url: str = KEV_URL) -> int:
    """Download CISA KEV and mark matching CVEs in DB. Returns count marked."""
    cve_ids = fetch_kev(url)
    count = mark_kev(conn, cve_ids)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)",
        (_META_KEY, now),
    )
    conn.commit()
    return count
