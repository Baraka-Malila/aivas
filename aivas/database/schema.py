import sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".aivas" / "aivas.db"


def get_db(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS cves (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT NOT NULL,
            published       TEXT,
            last_modified   TEXT,
            vuln_status     TEXT,
            cvss_score      REAL,
            cvss_severity   TEXT,
            cvss_vector     TEXT,
            attack_vector   TEXT,
            cwe_id          TEXT,
            kev             INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS cpe_matches (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id              TEXT NOT NULL REFERENCES cves(cve_id),
            cpe_criteria        TEXT NOT NULL,
            version_start_incl  TEXT,
            version_start_excl  TEXT,
            version_end_incl    TEXT,
            version_end_excl    TEXT,
            vulnerable          INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target          TEXT NOT NULL,
            started_at      TEXT NOT NULL,
            finished_at     TEXT,
            host_count      INTEGER DEFAULT 0,
            finding_count   INTEGER DEFAULT 0,
            risk_score      REAL,
            grade           TEXT,
            report_path     TEXT,
            scan_level      INTEGER DEFAULT 1,
            provider        TEXT DEFAULT 'groq'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL REFERENCES scans(id),
            host            TEXT NOT NULL,
            port            INTEGER,
            protocol        TEXT,
            service         TEXT,
            product         TEXT,
            version         TEXT,
            cve_id          TEXT,
            cvss_score      REAL,
            cvss_severity   TEXT,
            confidence      TEXT,
            en_risk         TEXT,
            sw_risk         TEXT,
            en_fix          TEXT,
            sw_fix          TEXT,
            resolved        INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sync_meta (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cpe_criteria
            ON cpe_matches(cpe_criteria);
        CREATE INDEX IF NOT EXISTS idx_cve_severity
            ON cves(cvss_severity);
        CREATE INDEX IF NOT EXISTS idx_findings_scan
            ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_host
            ON findings(host);
        CREATE INDEX IF NOT EXISTS idx_findings_cve
            ON findings(cve_id);
    """)
    conn.commit()
    # Migration: add kev column if DB predates this sprint
    try:
        conn.execute("ALTER TABLE cves ADD COLUMN kev INTEGER DEFAULT 0")
        conn.commit()
    except Exception:
        pass  # column already exists
