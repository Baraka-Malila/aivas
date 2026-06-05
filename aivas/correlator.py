import sqlite3
from aivas.database.cpe_query import find_cves

NSE_CVE_MAP: dict[str, str] = {
    "http-shellshock": "CVE-2014-6271",
    "smb-vuln-ms17-010": "CVE-2017-0144",
    "smb-vuln-cve2009-3103": "CVE-2009-3103",
    "ftp-vsftpd-backdoor": "CVE-2011-2523",
    "ftp-proftpd-backdoor": "CVE-2010-4221",
    "http-vuln-cve2017-5638": "CVE-2017-5638",
}


def _nse_confirmed_cve_ids(services: list[dict]) -> set[str]:
    confirmed = set()
    for svc in services:
        for script_id, output in svc.get("nse_results", {}).items():
            if "VULNERABLE" in output and script_id in NSE_CVE_MAP:
                confirmed.add(NSE_CVE_MAP[script_id])
    return confirmed


def correlate(conn: sqlite3.Connection, services: list[dict]) -> list[dict]:
    seen: set[str] = set()
    findings: list[dict] = []
    confirmed_ids = _nse_confirmed_cve_ids(services)

    for svc in services:
        product = f"{svc.get('product', '')} {svc.get('service', '')}".strip()
        version = svc.get("version") or None
        for row in find_cves(conn, product, version):
            cve_id = row["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            confidence = "confirmed" if cve_id in confirmed_ids else row["confidence"]
            findings.append({**row, "confidence": confidence, "host": svc["host"]})

    for cve_id in confirmed_ids:
        if cve_id not in seen:
            row = conn.execute(
                "SELECT cve_id, cvss_score, cvss_severity, description FROM cves WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()
            if row:
                seen.add(cve_id)
                findings.append({**dict(row), "confidence": "confirmed"})

    findings.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    return findings
