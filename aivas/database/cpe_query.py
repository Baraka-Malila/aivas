import re
import sqlite3
from packaging.version import Version, InvalidVersion

PRODUCT_CPE_MAP = {
    "apache httpd": "apache:http_server",
    "nginx": "nginx:nginx",
    "openssh": "openbsd:openssh",
    "openssl": "openssl:openssl",
    "mysql": "mysql:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "vsftpd": "vsftpd:vsftpd",
    "proftpd": "proftpd:proftpd",
    "microsoft iis": "microsoft:iis",
    "php": "php:php",
    "samba": "samba:samba",
    "dovecot": "dovecot:dovecot",
    "postfix": "postfix:postfix",
    "sendmail": "sendmail:sendmail",
    "bind": "isc:bind",
    "tomcat": "apache:tomcat",
    "lighttpd": "lighttpd:lighttpd",
    "filezilla": "filezilla-project:filezilla_server",
}


def normalize_product(product: str) -> str | None:
    key = product.lower().strip()
    for pattern, cpe_frag in PRODUCT_CPE_MAP.items():
        if pattern in key:
            return cpe_frag
    return None


def _parse_version(raw: str) -> Version | None:
    """Normalize common non-PEP-440 patterns then parse."""
    v = re.sub(r'p(\d+)', r'.\1', raw)    # 8.9p1 → 8.9.1
    v = re.sub(r'[+~].*', '', v)           # strip build metadata
    v = re.sub(r'[a-zA-Z].*$', '', v)     # strip trailing alpha suffixes
    v = v.strip('.-')
    try:
        return Version(v) if v else None
    except InvalidVersion:
        return None


def _cpe_version(criteria: str) -> str | None:
    """Return the version field from a CPE 2.3 string, or None if wildcard."""
    parts = (criteria or "").split(":")
    if len(parts) < 6:
        return None
    v = parts[5]
    return None if v in ("*", "-", "") else v


def _in_version_range(detected: Version, row: sqlite3.Row) -> bool:
    """True if detected falls within the row's version bounds."""
    checks = [
        (row["version_start_incl"], lambda d, b: d < b),
        (row["version_start_excl"], lambda d, b: d <= b),
        (row["version_end_incl"],   lambda d, b: d > b),
        (row["version_end_excl"],   lambda d, b: d >= b),
    ]
    for bound, out_of_range in checks:
        if not bound:
            continue
        b = _parse_version(bound)
        if b is not None and out_of_range(detected, b):
            return False
    return True


def find_cves(
    conn: sqlite3.Connection,
    product: str,
    version: str | None,
) -> list[dict]:
    cpe_frag = normalize_product(product)
    if not cpe_frag:
        return []

    rows = conn.execute(
        """SELECT c.cve_id, c.cvss_score, c.cvss_severity, c.description,
                  c.cvss_vector, c.attack_vector, c.cwe_id,
                  m.cpe_criteria, m.version_start_incl, m.version_start_excl,
                  m.version_end_incl, m.version_end_excl
           FROM cpe_matches m
           JOIN cves c ON m.cve_id = c.cve_id
           WHERE m.cpe_criteria LIKE ? AND m.vulnerable = 1
             AND c.cvss_score IS NOT NULL""",
        (f"%{cpe_frag}%",),
    ).fetchall()

    if not version:
        seen: set[str] = set()
        results = []
        for r in rows:
            if r["cve_id"] not in seen:
                seen.add(r["cve_id"])
                results.append(dict(r) | {"confidence": "possible"})
        results.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
        return results

    detected = _parse_version(version)
    if detected is None:
        seen = set()
        results = []
        for r in rows:
            if r["cve_id"] not in seen:
                seen.add(r["cve_id"])
                results.append(dict(r) | {"confidence": "possible"})
        results.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
        return results

    # Per-CVE best confidence: probable beats possible
    best: dict[str, dict] = {}
    for row in rows:
        cve_id = row["cve_id"]
        has_range = any([
            row["version_start_incl"], row["version_start_excl"],
            row["version_end_incl"],   row["version_end_excl"],
        ])
        cpe_ver = _cpe_version(row["cpe_criteria"] or "")

        if has_range:
            if not _in_version_range(detected, row):
                continue
            conf = "probable"
        elif cpe_ver:
            # Exact version in CPE — only match if detected equals it
            cv = _parse_version(cpe_ver)
            if cv is None or detected != cv:
                continue
            conf = "probable"
        else:
            # Wildcard CPE with no range — product matches but version unknown
            conf = "possible"

        if cve_id not in best or conf == "probable":
            best[cve_id] = dict(row) | {"confidence": conf}

    matched = list(best.values())
    matched.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    return matched
