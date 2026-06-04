import json
import sqlite3
from pathlib import Path
from typing import Iterator


def parse_cve_data(data: dict) -> dict | None:
    """Extract CVE record from NVD JSON entry."""
    cve_id = data.get("id")
    if not cve_id:
        return None

    description = next(
        (d["value"] for d in data.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    cvss_score = cvss_severity = cvss_vector = attack_vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = data.get("metrics", {}).get(key, [])
        primary = next(
            (m for m in metrics if m.get("type") == "Primary"),
            metrics[0] if metrics else None,
        )
        if primary:
            cd = primary.get("cvssData", {})
            cvss_score = cd.get("baseScore")
            cvss_severity = cd.get("baseSeverity")
            cvss_vector = cd.get("vectorString")
            attack_vector = cd.get("attackVector")
            break

    cwe_id = None
    for weakness in data.get("weaknesses", []):
        if weakness.get("type") == "Primary":
            descs = weakness.get("description", [])
            if descs:
                cwe_id = descs[0].get("value")
                break

    cpe_matches = []
    for config in data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_matches.append({
                    "cpe_criteria": match.get("criteria", ""),
                    "version_start_incl": match.get("versionStartIncluding"),
                    "version_start_excl": match.get("versionStartExcluding"),
                    "version_end_incl": match.get("versionEndIncluding"),
                    "version_end_excl": match.get("versionEndExcluding"),
                    "vulnerable": 1 if match.get("vulnerable", True) else 0,
                })

    return {
        "cve_id": cve_id,
        "description": description,
        "published": data.get("published"),
        "last_modified": data.get("lastModified"),
        "vuln_status": data.get("vulnStatus"),
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "attack_vector": attack_vector,
        "cwe_id": cwe_id,
        "cpe_matches": cpe_matches,
    }


def insert_cve(conn: sqlite3.Connection, record: dict) -> None:
    """Insert a parsed CVE record and its CPE matches into database."""
    cpe_list = record.pop("cpe_matches", [])
    conn.execute(
        """INSERT OR IGNORE INTO cves
           (cve_id, description, published, last_modified, vuln_status,
            cvss_score, cvss_severity, cvss_vector, attack_vector, cwe_id)
           VALUES (:cve_id, :description, :published, :last_modified, :vuln_status,
                   :cvss_score, :cvss_severity, :cvss_vector, :attack_vector, :cwe_id)""",
        record,
    )
    conn.executemany(
        """INSERT OR IGNORE INTO cpe_matches
           (cve_id, cpe_criteria, version_start_incl, version_start_excl,
            version_end_incl, version_end_excl, vulnerable)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                record["cve_id"],
                m["cpe_criteria"],
                m["version_start_incl"],
                m["version_start_excl"],
                m["version_end_incl"],
                m["version_end_excl"],
                m["vulnerable"],
            )
            for m in cpe_list
        ],
    )
    record["cpe_matches"] = cpe_list  # restore so caller's dict is unchanged
    conn.commit()


def _iter_cve_files(feeds_dir: Path) -> Iterator[Path]:
    """Iterate CVE JSON files in nvd-json-data-feeds structure."""
    for year_dir in sorted(feeds_dir.glob("CVE-*")):
        if not year_dir.is_dir():
            continue
        for range_dir in sorted(year_dir.glob("CVE-*")):
            if not range_dir.is_dir():
                continue
            yield from sorted(range_dir.glob("CVE-*.json"))


def ingest_feeds(
    conn: sqlite3.Connection,
    feeds_dir: Path,
    progress_callback=None,
) -> int:
    """Ingest all CVE JSON files from feeds_dir into database."""
    inserted = 0
    batch_cves: list[dict] = []
    batch_cpes: list[tuple] = []

    def flush():
        nonlocal inserted
        conn.executemany(
            """INSERT OR IGNORE INTO cves
               (cve_id, description, published, last_modified, vuln_status,
                cvss_score, cvss_severity, cvss_vector, attack_vector, cwe_id)
               VALUES (:cve_id, :description, :published, :last_modified, :vuln_status,
                       :cvss_score, :cvss_severity, :cvss_vector, :attack_vector, :cwe_id)""",
            batch_cves,
        )
        inserted += conn.execute("SELECT changes()").fetchone()[0]
        conn.executemany(
            """INSERT OR IGNORE INTO cpe_matches
               (cve_id, cpe_criteria, version_start_incl, version_start_excl,
                version_end_incl, version_end_excl, vulnerable)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            batch_cpes,
        )
        conn.commit()
        batch_cves.clear()
        batch_cpes.clear()

    for i, path in enumerate(iter(list(_iter_cve_files(feeds_dir)))):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        record = parse_cve_data(data)
        if not record:
            continue

        cpe_list = record.pop("cpe_matches")
        batch_cves.append(record)
        for cpe in cpe_list:
            batch_cpes.append((
                record["cve_id"],
                cpe["cpe_criteria"],
                cpe["version_start_incl"],
                cpe["version_start_excl"],
                cpe["version_end_incl"],
                cpe["version_end_excl"],
                cpe["vulnerable"],
            ))

        if len(batch_cves) >= 1000:
            flush()
            if progress_callback:
                progress_callback(i + 1)

    if batch_cves:
        flush()

    return inserted
