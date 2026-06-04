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


def _in_version_range(detected: Version, row: sqlite3.Row) -> bool:
    try:
        if row["version_start_incl"] and detected < Version(row["version_start_incl"]):
            return False
        if row["version_start_excl"] and detected <= Version(row["version_start_excl"]):
            return False
        if row["version_end_incl"] and detected > Version(row["version_end_incl"]):
            return False
        if row["version_end_excl"] and detected >= Version(row["version_end_excl"]):
            return False
        return True
    except InvalidVersion:
        return False


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
                  m.version_start_incl, m.version_start_excl,
                  m.version_end_incl, m.version_end_excl
           FROM cpe_matches m
           JOIN cves c ON m.cve_id = c.cve_id
           WHERE m.cpe_criteria LIKE ? AND m.vulnerable = 1
             AND c.cvss_score IS NOT NULL""",
        (f"%{cpe_frag}%",),
    ).fetchall()

    if not version:
        results = [dict(r) | {"confidence": "possible"} for r in rows]
        results.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
        return results

    try:
        detected = Version(version)
    except InvalidVersion:
        results = [dict(r) | {"confidence": "possible"} for r in rows]
        results.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
        return results

    matched = []
    for row in rows:
        has_range = any([
            row["version_start_incl"],
            row["version_start_excl"],
            row["version_end_incl"],
            row["version_end_excl"],
        ])
        if not has_range or _in_version_range(detected, row):
            matched.append(dict(row) | {"confidence": "probable"})

    matched.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    return matched
