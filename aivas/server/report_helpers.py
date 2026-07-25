"""Shared helper functions for HTML/PDF report generation."""
from __future__ import annotations

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_GRADE_LABEL = {
    "A": "No significant vulnerabilities found",
    "B": "Minor issues detected — low risk",
    "C": "Notable vulnerabilities present",
    "D": "Significant vulnerabilities require attention",
    "F": "Immediate remediation required",
}

_RCE = {"remote code execution", "rce", "arbitrary code", "execute code", "arbitrary command"}
_SQLI = {"sql injection", "sqli", "sql query"}
_AUTH = {"authentication bypass", "bypass authentication", "unauthenticated access"}
_DOS = {"denial of service", " dos ", "resource exhaustion", "crash"}
_PRIV = {"privilege escalation", "local privilege", "root access", "elevate privilege"}
_XSS = {"cross-site scripting", "xss", "script injection"}
_BUF = {"buffer overflow", "stack overflow", "heap overflow", "out-of-bounds write"}
_TRAV = {"path traversal", "directory traversal", "file inclusion"}


def cve_fix(f: dict, conn: "sqlite3.Connection | None" = None, lang: str = "en") -> str:
    """Three-tier remediation lookup:
       1. Stored on the finding (from narrator path) → return.
       2. Cached in cve_advice table → return.
       3. Legacy template by description keyword → return.
    """
    fix_field = f.get(f"fix_{lang}") or ""
    fix_field = fix_field.strip()
    if fix_field:
        return fix_field

    cve_id = f.get("cve_id", "")
    if conn is not None and cve_id:
        from aivas.server.cve_advice import get_advice
        cached = get_advice(conn, cve_id)
        if cached:
            return cached.get(f"advice_{lang}", "") or cached.get("advice_en", "")

    return _legacy_template_fix(f, lang)


def _legacy_template_fix(f: dict, lang: str = "en") -> str:
    """Existing keyword-switch fallback; honest as a fallback, dishonest as primary."""
    desc = (f.get("description") or "").lower()
    cve = f.get("cve_id", "")
    if any(t in desc for t in _RCE):
        action = "Apply vendor patch immediately. Isolate the service from the internet until resolved."
    elif any(t in desc for t in _SQLI):
        action = "Patch the application. Audit SQL queries to ensure parameterized inputs are used."
    elif any(t in desc for t in _AUTH):
        action = "Apply patch immediately. Enforce strong authentication and audit all access controls."
    elif any(t in desc for t in _DOS):
        action = "Apply patch. Implement rate limiting and upstream firewall filtering."
    elif any(t in desc for t in _PRIV):
        action = "Apply patch. Restrict user privileges and audit sudoers and group memberships."
    elif any(t in desc for t in _XSS):
        action = "Apply patch. Enforce a strict Content Security Policy on the web application."
    elif any(t in desc for t in _BUF):
        action = "Apply vendor patch. Ensure ASLR and DEP/NX protections are enabled on the host."
    elif any(t in desc for t in _TRAV):
        action = "Apply patch. Restrict filesystem permissions and validate all file path inputs."
    else:
        action = "Update to the latest patched version. Monitor vendor security advisories."
    return f"{cve}: {action}"


def executive_summary(grade: str, score: int, target: str, findings: list[dict]) -> str:
    n = len(findings)
    by = {s: [f for f in findings if f.get("cvss_severity") == s] for s in _SEV_ORDER}
    nc, nh = len(by["CRITICAL"]), len(by["HIGH"])
    label = _GRADE_LABEL.get(grade, "Unknown risk level")
    if nc:
        risk = (f"{nc} critical CVE(s) identified that may allow remote code execution or full "
                f"system compromise without authentication. Immediate patching is required.")
    elif nh:
        risk = (f"{nh} high-severity CVE(s) identified. Prompt remediation is required to "
                f"prevent exploitation by network-adjacent attackers.")
    elif n:
        risk = f"{n} lower-severity CVE(s) identified. Schedule remediation within 30 days."
    else:
        risk = "No CVEs matched in the local database. Verify that services are fully up to date."

    body = (f"Host <strong>{target}</strong> received a risk score of <strong>{score}/100</strong> "
            f"(Grade <strong>{grade}</strong> — {label}). {risk}")

    kev_n = sum(1 for f in findings if f.get("kev"))
    if kev_n:
        unit = "vulnerability" if kev_n == 1 else "vulnerabilities"
        kev_note = (
            f"<strong>WARNING — {kev_n} actively-exploited {unit} detected.</strong> "
            "These CVEs are in CISA's Known Exploited Vulnerabilities catalog — "
            "confirmed in-the-wild attacks. Remediation cannot wait. "
        )
        return kev_note + body
    return body


def sev_summary_rows(findings: list[dict]) -> str:
    by = {s: [f for f in findings if f.get("cvss_severity") == s] for s in _SEV_ORDER}
    impacts = {
        "CRITICAL": "May allow remote code execution or full system compromise without authentication",
        "HIGH": "May allow significant data breach, unauthorised access, or service disruption",
        "MEDIUM": "May allow limited unauthorised access or sensitive information disclosure",
        "LOW": "Minor risk; limited impact under normal operating conditions",
    }
    rows = "".join(
        f"<tr><td>{sev}</td><td style='text-align:center'>{len(by[sev])}</td>"
        f"<td>{impacts[sev]}</td></tr>"
        for sev in _SEV_ORDER if by[sev]
    )
    return rows or "<tr><td colspan='3' style='color:#666;padding:8px'>No findings recorded.</td></tr>"
