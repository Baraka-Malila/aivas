import sqlite3
from datetime import datetime, timezone


def _grade(max_score: float | None) -> str:
    if max_score is None:
        return "PASS"
    if max_score >= 9.0:
        return "CRITICAL"
    if max_score >= 7.0:
        return "HIGH"
    if max_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def save_scan(
    conn: sqlite3.Connection,
    target: str,
    findings: list[dict],
    report_path: str | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    scores = [f["cvss_score"] for f in findings if f.get("cvss_score")]
    max_score = max(scores) if scores else None
    hosts = {f.get("host") for f in findings if f.get("host")}

    cur = conn.execute(
        """INSERT INTO scans
               (target, started_at, finished_at, host_count, finding_count,
                risk_score, grade, report_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (target, now, now, len(hosts), len(findings),
         max_score, _grade(max_score), report_path),
    )
    scan_id = cur.lastrowid

    conn.executemany(
        """INSERT INTO findings
               (scan_id, host, cve_id, cvss_score, cvss_severity, confidence,
                en_risk, sw_risk)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                scan_id,
                f.get("host") or "",
                f["cve_id"],
                f.get("cvss_score"),
                f.get("cvss_severity"),
                f.get("confidence"),
                f.get("narration_en"),
                f.get("narration_sw"),
            )
            for f in findings
        ],
    )
    conn.commit()
    return scan_id


def list_scans(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        """SELECT id, target, started_at, finding_count, risk_score, grade
           FROM scans ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def diff_scans(conn: sqlite3.Connection, old_id: int, new_id: int) -> dict[str, list]:
    def _cve_ids(scan_id: int) -> set[str]:
        rows = conn.execute(
            "SELECT DISTINCT cve_id FROM findings WHERE scan_id = ? AND cve_id IS NOT NULL",
            (scan_id,),
        ).fetchall()
        return {r["cve_id"] for r in rows}

    old_cves = _cve_ids(old_id)
    new_cves = _cve_ids(new_id)
    return {
        "new": sorted(new_cves - old_cves),
        "fixed": sorted(old_cves - new_cves),
        "common": sorted(old_cves & new_cves),
    }
