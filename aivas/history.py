import sqlite3
from datetime import datetime, timezone
from aivas.scorer import score_findings


def save_scan(
    conn: sqlite3.Connection,
    target: str,
    findings: list[dict],
    report_path: str | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    scored = score_findings(findings)
    hosts = {f.get("host") for f in findings if f.get("host")}

    cur = conn.execute(
        """INSERT INTO scans
               (target, started_at, finished_at, host_count, finding_count,
                risk_score, grade, report_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (target, now, now, len(hosts), len(findings),
         scored["score"], f"Grade {scored['grade']}", report_path),
    )
    scan_id = cur.lastrowid

    conn.executemany(
        """INSERT INTO findings
               (scan_id, host, cve_id, cvss_score, cvss_severity, confidence,
                en_risk, sw_risk, en_fix, sw_fix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                f.get("fix_en"),
                f.get("fix_sw"),
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


def get_scan_meta(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, target, started_at, finished_at, finding_count, risk_score, grade "
        "FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    return dict(row) if row else None


def get_scan_findings(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    rows = conn.execute(
        """SELECT f.host, f.cve_id, f.cvss_score, f.cvss_severity, f.confidence,
                  f.en_risk, f.sw_risk, f.en_fix, f.sw_fix, c.description
           FROM findings f
           LEFT JOIN cves c ON c.cve_id = f.cve_id
           WHERE f.scan_id = ?""",
        (scan_id,),
    ).fetchall()
    return [
        {
            "host": r["host"],
            "cve_id": r["cve_id"],
            "cvss_score": r["cvss_score"],
            "cvss_severity": r["cvss_severity"],
            "confidence": r["confidence"],
            "narration_en": r["en_risk"] or "",
            "narration_sw": r["sw_risk"] or "",
            "fix_en": r["en_fix"] or "",
            "fix_sw": r["sw_fix"] or "",
            "description": r["description"] or "",
        }
        for r in rows
    ]
