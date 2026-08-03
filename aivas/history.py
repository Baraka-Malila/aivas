import sqlite3
from datetime import datetime, timezone
from aivas.scorer import score_findings


def save_scan(
    conn: sqlite3.Connection,
    target: str,
    findings: list[dict],
    report_path: str | None = None,
    user_id: int | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    scored = score_findings(findings)
    hosts = {f.get("host") for f in findings if f.get("host")}

    date_str = datetime.now(timezone.utc).strftime("%b %d")
    grade = scored["grade"]
    auto_label = f"{target} — Grade {grade} — {date_str}"
    cur = conn.execute(
        """INSERT INTO scans
               (target, label, started_at, finished_at, host_count, finding_count,
                risk_score, grade, report_path, user_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (target, auto_label, now, now, len(hosts), len(findings),
         scored["score"], f"Grade {scored['grade']}", report_path, user_id),
    )
    scan_id = cur.lastrowid

    conn.executemany(
        """INSERT INTO findings
               (scan_id, host, cve_id, cvss_score, cvss_severity, confidence,
                en_risk, sw_risk, en_fix, sw_fix, version)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                f.get("installed_version"),
            )
            for f in findings
        ],
    )
    conn.commit()
    return scan_id


def list_scans(
    conn: sqlite3.Connection, limit: int = 20, offset: int = 0, user_id: int | None = None
) -> list[dict]:
    if user_id is not None:
        where = "WHERE s.user_id = ?"
        params: tuple = (user_id, limit, offset)
    else:
        where = ""
        params = (limit, offset)
    rows = conn.execute(
        f"""
        SELECT s.id, s.target, s.label, s.started_at, s.finding_count, s.risk_score, s.grade,
               COALESCE((
                 SELECT COUNT(DISTINCT f.cve_id)
                   FROM findings f
                   JOIN cves c ON c.cve_id = f.cve_id
                  WHERE f.scan_id = s.id AND c.kev = 1
               ), 0) AS kev_count,
               COALESCE((
                 SELECT COUNT(DISTINCT f.cve_id)
                   FROM findings f
                   JOIN cves c ON c.cve_id = f.cve_id
                  WHERE f.scan_id = s.id AND c.cvss_severity = 'CRITICAL'
               ), 0) AS critical_count
          FROM scans s
          {where}
         ORDER BY s.id DESC
         LIMIT ? OFFSET ?
        """,
        params,
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
                  f.en_risk, f.sw_risk, f.en_fix, f.sw_fix, f.version,
                  c.description, c.kev
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
            "installed_version": r["version"] or "",
            "description": r["description"] or "",
            "kev": bool(r["kev"]),
        }
        for r in rows
    ]
