"""Streaming analysis for ScanCard — emits NDJSON events like the chat WebSocket."""
from __future__ import annotations

import json
import logging
import re
import sqlite3

_log = logging.getLogger("aivas.analyze")

_LANG_DIRECTIVE = {
    "auto": "Respond in ENGLISH by default. Switch to Swahili only if the user message clearly contains Swahili words.",
    "en": "Always respond in English.",
    "sw": "Always respond in Swahili (Kiswahili). Do not include English translations.",
}

_PROVIDER_DEFAULTS = {
    "groq": "llama-3.1-8b-instant",
    "claude": "claude-haiku-4-5-20251001",
    "ollama": "llama3",
}

# Software detection from CVE descriptions
_SOFTWARE_PATTERNS = [
    (r'apache http server|mod_rewrite|mod_ssl|mod_proxy|mod_auth|httpd', 'Apache HTTP Server', 'https://httpd.apache.org/'),
    (r'openssh',             'OpenSSH',             'https://www.openssh.com/'),
    (r'openssl',             'OpenSSL',             'https://www.openssl.org/'),
    (r'nginx',               'nginx',               'https://nginx.org/'),
    (r'mysql',               'MySQL',               'https://dev.mysql.com/'),
    (r'mariadb',             'MariaDB',             'https://mariadb.org/'),
    (r'\bphp\b',             'PHP',                 'https://www.php.net/'),
    (r'linux kernel|\bkernel\b', 'Linux Kernel',    'https://kernel.org/'),
    (r'wordpress',           'WordPress',           'https://wordpress.org/'),
    (r'samba',               'Samba',               'https://www.samba.org/'),
    (r'\bbind\b|named|dns-over-https|isc bind', 'BIND (ISC)', 'https://www.isc.org/bind/'),
    (r'sudo',                'sudo',                'https://www.sudo.ws/'),
    (r'glibc|gnu c library', 'glibc',               'https://www.gnu.org/software/libc/'),
    (r'curl|libcurl',        'curl',                'https://curl.se/'),
    (r'python',              'Python',              'https://www.python.org/'),
    (r'postgresql',          'PostgreSQL',          'https://www.postgresql.org/'),
    (r'redis',               'Redis',               'https://redis.io/'),
    (r'docker|moby',         'Docker',              'https://docs.docker.com/'),
    (r'git\b',               'Git',                 'https://git-scm.com/'),
    (r'vim\b',               'Vim',                 'https://www.vim.org/'),
    (r'expat|libexpat',      'Expat XML',           'https://libexpat.github.io/'),
    (r'zlib',                'zlib',                'https://zlib.net/'),
    (r'log4j',               'Log4j',               'https://logging.apache.org/log4j/'),
]


def _ev(obj: dict) -> str:
    return json.dumps(obj) + "\n"


def _extract_fix_version(description: str) -> str | None:
    patterns = [
        r'upgrade to version ([\d]+\.[\d]+(?:\.[\d]+)?)',
        r'updating to (?:version )?([\d]+\.[\d]+(?:\.[\d]+)?)',
        r'version ([\d]+\.[\d]+(?:\.[\d]+)?),? which fixes',
        r'fixed in (?:version )?([\d]+\.[\d]+(?:\.[\d]+)?)',
    ]
    for p in patterns:
        m = re.search(p, description, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_current_version(description: str) -> str | None:
    m = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)?)\s+and\s+earlier', description, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'through\s+([\d]+\.[\d]+(?:\.[\d]+)?)', description, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def _detect_software(description: str) -> tuple[str, str] | tuple[None, None]:
    dl = description.lower()
    for pattern, name, url in _SOFTWARE_PATTERNS:
        if re.search(pattern, dl):
            return name, url
    return None, None


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("cvss_severity") or "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _findings_summary(findings: list[dict]) -> str:
    counts = _severity_counts(findings)
    parts = [f"{v} {k.lower()}" for k, v in counts.items() if v > 0]
    kev_count = sum(1 for f in findings if f.get("kev"))
    base = f"{len(findings)} finding{'s' if len(findings) != 1 else ''}"
    if parts:
        base += f" ({', '.join(parts)})"
    if kev_count:
        base += f", {kev_count} KEV"
    return base


def _build_risk_prompt(meta: dict, findings: list[dict]) -> str:
    grade = (meta.get("grade") or "?").replace("Grade ", "")
    target = meta.get("target", "unknown")

    # Guard: 0 findings — no hallucination allowed
    if not findings:
        return (
            f"Scan data: target={target}, grade={grade}, 0 vulnerabilities found.\n\n"
            "Write a 3-paragraph security brief. No lists. No headers. Three paragraphs only.\n\n"
            "Paragraph 1 — Posture: State that the scan returned Grade A with zero vulnerabilities found. "
            "Explain what this means in plain language — the exposed services appear secure based on known CVEs.\n\n"
            "Paragraph 2 — Limitations: Note that a network scan has limits — it cannot see inside the machine, "
            "check user access controls, or detect unknown vulnerabilities. "
            "A clean scan is a good sign but not a guarantee of full security.\n\n"
            "Paragraph 3 — Recommendation: Advise keeping software updated, rescanning periodically, "
            "and reviewing user access and firewall rules as complementary steps. "
            "No invented vulnerabilities. No CVE IDs. No guessing."
        )

    counts = _severity_counts(findings)
    kev_count = sum(1 for f in findings if f.get("kev"))

    # Find the worst finding: KEV first, then highest CVSS
    top = max(findings, key=lambda x: (x.get("kev") or False, x.get("cvss_score") or 0), default=None)
    top_line = ""
    if top:
        kev_note = " — currently being actively exploited in the wild" if top.get("kev") else ""
        top_line = (
            f"Worst finding: {top['cve_id']} "
            f"(CVSS {top.get('cvss_score', '?')}, {top.get('cvss_severity', '?')}{kev_note}) "
            f"— {(top.get('description') or '')[:250]}"
        )

    count_str = ", ".join(f"{v} {k.lower()}" for k, v in counts.items() if v > 0)
    kev_str = f", {kev_count} actively exploited in the wild" if kev_count > 0 else ""
    urgency = "CRITICAL — immediate action required" if counts.get("CRITICAL", 0) > 0 else (
        "HIGH — action required within days" if counts.get("HIGH", 0) > 0 else "action recommended"
    )

    return (
        f"Scan data: target={target}, grade={grade}, "
        f"{len(findings)} findings ({count_str}{kev_str}). Urgency: {urgency}.\n"
        f"{top_line}\n\n"
        "Write a 3-paragraph executive risk brief. No lists. No headers. Exactly three paragraphs.\n\n"
        "Paragraph 1 — Posture: State the grade and what it means for the organization in plain language. "
        "List the finding count by severity. Keep it factual and direct.\n\n"
        "Paragraph 2 — Primary Threat: Name the worst vulnerability — what software it affects, "
        "what an attacker can do, and whether it is being actively exploited right now. "
        "If no KEV exists, describe the most severe CVE found. "
        "Do not invent vulnerabilities not in the scan data above.\n\n"
        "Paragraph 3 — Urgency and Action: Describe how urgent this is based on the severity above. "
        "Do NOT say '24 hours' or give specific time estimates — use urgency language (immediate, this week, etc.). "
        "Refer to 'the system owner' or 'the IT team', not 'our team' or 'our organization'. "
        "Describe the type of action needed in plain language — no shell commands, no package names."
    )


def _build_remediation_prompt(meta: dict, findings: list[dict]) -> str:
    target = meta.get("target", "unknown")

    if not findings:
        return (
            f"Scan of {target} found no vulnerabilities. "
            "Write one short paragraph: no remediation is needed based on this scan. "
            "Recommend periodic rescanning and general security hygiene."
        )

    # Pre-process: group by software, extract versions from descriptions
    # Key: (severity, software_name)
    groups: dict[tuple, dict] = {}
    ungrouped: list[dict] = []

    sorted_f = sorted(findings, key=lambda x: (not x.get("kev"), -(x.get("cvss_score") or 0)))

    for f in sorted_f:
        sev = (f.get("cvss_severity") or "LOW").upper()
        desc = f.get("description") or ""
        software, url = _detect_software(desc)
        fix_ver = _extract_fix_version(desc)
        curr_ver = _extract_current_version(desc)

        # Prefer the actual installed version recorded by the probe over regex extraction
        installed_ver = f.get("installed_version") or None

        if software:
            key = (sev, software)
            if key not in groups:
                groups[key] = {
                    "software": software,
                    "url": url,
                    "severity": sev,
                    "kev": False,
                    "cves": [],
                    "fix_versions": set(),
                    "current_versions": set(),
                }
            g = groups[key]
            g["kev"] = g["kev"] or bool(f.get("kev"))
            g["cves"].append(f["cve_id"])
            if fix_ver:
                g["fix_versions"].add(fix_ver)
            # Use probe-recorded version first; fall back to CVE description regex
            best_curr = installed_ver or curr_ver
            if best_curr:
                g["current_versions"].add(best_curr)
        else:
            ungrouped.append({
                "cve_id": f["cve_id"],
                "severity": sev,
                "kev": bool(f.get("kev")),
                "desc": desc[:180],
                "fix_ver": fix_ver,
                "curr_ver": installed_ver or curr_ver,
            })

    lines = [f"Target: {target}\nGrouped findings (pre-processed):\n"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_groups = [(k, g) for k, g in groups.items() if g["severity"] == sev]
        sev_ung = [u for u in ungrouped if u["severity"] == sev]
        if not sev_groups and not sev_ung:
            continue
        lines.append(f"\n  {sev}:")
        for _, g in sev_groups:
            kev = " [URGENT — actively exploited]" if g["kev"] else ""
            cves = ", ".join(g["cves"][:6])
            if len(g["cves"]) > 6:
                cves += f" + {len(g['cves'])-6} more"
            fix = max(g["fix_versions"]) if g["fix_versions"] else "unknown"
            curr = max(g["current_versions"]) if g["current_versions"] else "unknown"
            lines.append(
                f"    Software: {g['software']}{kev}\n"
                f"    CVEs: {cves}\n"
                f"    Installed version: {curr}\n"
                f"    Fix version: {fix}\n"
                f"    Vendor: {g['url']}\n"
            )
        for u in sev_ung:
            kev = " [URGENT — actively exploited]" if u["kev"] else ""
            fix = u["fix_ver"] or "unknown"
            lines.append(
                f"    {u['cve_id']}{kev}: {u['desc'][:120]}\n"
                f"    Fix version: {fix}\n"
            )

    block = "\n".join(lines)

    return (
        f"{block}\n\n"
        "Write a remediation plan using the pre-processed data above. "
        "Use severity headers (## CRITICAL, ## HIGH, ## MEDIUM, ## LOW). "
        "Under each header, write one numbered entry per software group:\n"
        "  1. Software name + CVE list (abbreviated if long)\n"
        "  2. Installed version (from 'Installed version' field above, or 'unknown')\n"
        "  3. Fix version — use the EXACT version from the 'Fix version' field above. "
        "If fix version is 'unknown', write: 'Update to the latest stable release.'\n"
        "  4. ONE action: 'Update via your OS package manager, or download from <Vendor URL from data above>.'\n"
        "     Use the EXACT vendor URL from the 'Vendor:' field above — do not invent or omit it.\n\n"
        "RULES: No shell commands (apt, dnf, etc.) — OS is unknown. "
        "Combine all CVEs for the same software into one entry. "
        "If [URGENT — actively exploited], prepend the entry with '⚠ URGENT: '. "
        "For ungrouped CVEs (no software detected), write a brief one-line action based on the description. "
        "If no fix information is available, write: 'Monitor vendor advisories for a patch.' "
        "Omit empty severity sections."
    )


def _resolve_api_key(provider_name: str, api_key: str | None) -> str | None:
    if api_key:
        return api_key
    if provider_name == "groq":
        try:
            from aivas import config as _cfg
            key = _cfg.load().get("api_key")
            if key:
                return key
        except Exception:
            pass
        import os
        return os.environ.get("GROQ_API_KEY") or None
    return None


async def stream_analysis(
    conn: sqlite3.Connection,
    scan_id: int,
    analysis_type: str,
    provider_name: str,
    model: str | None,
    api_key: str | None,
    lang: str = "auto",
):
    """Yield newline-delimited JSON events compatible with the chat WebSocket protocol."""
    from aivas.history import get_scan_meta, get_scan_findings
    from aivas.narrator.providers.factory import get_provider

    yield _ev({"type": "tool_call", "name": "get_scan_findings", "args": {"scan_id": scan_id}})

    meta = get_scan_meta(conn, scan_id)
    if meta is None:
        yield _ev({"type": "error", "text": "Scan not found."})
        return

    findings = get_scan_findings(conn, scan_id)
    yield _ev({
        "type": "tool_result",
        "name": "get_scan_findings",
        "summary": _findings_summary(findings),
    })

    if analysis_type == "risk_summary":
        user_prompt = _build_risk_prompt(meta, findings)
        system = (
            "You are a concise security advisor writing executive briefs. "
            "Use only the data provided. Never invent CVEs, software names, or vulnerabilities "
            "not present in the scan data. Follow the paragraph structure exactly."
        )
        max_tokens = 450
    else:
        user_prompt = _build_remediation_prompt(meta, findings)
        system = (
            "You are a security engineer writing remediation guidance. "
            "Use only the pre-processed data provided. "
            "Never write shell commands. Group CVEs by software as instructed."
        )
        max_tokens = 900

    lang_note = _LANG_DIRECTIVE.get(lang) or _LANG_DIRECTIVE["auto"]
    messages = [
        {"role": "system", "content": f"{system}\n\n{lang_note}"},
        {"role": "user", "content": user_prompt},
    ]

    chosen_model = model or _PROVIDER_DEFAULTS.get(provider_name, "llama-3.1-8b-instant")
    resolved_key = _resolve_api_key(provider_name, api_key)

    try:
        provider = get_provider(provider_name, model=chosen_model, api_key=resolved_key)
    except ValueError as exc:
        yield _ev({"type": "error", "text": str(exc)})
        return

    try:
        async for token in provider.stream(messages, max_tokens=max_tokens):
            yield _ev({"type": "token", "text": token})
    except Exception as exc:
        _log.error("analyze_stream error [%s]: %s", analysis_type, exc)
        s = str(exc)
        if "429" in s or "rate_limit" in s.lower():
            yield _ev({"type": "token", "text": "\n\n*Rate limit reached — please wait a moment.*"})
        else:
            yield _ev({"type": "error", "text": str(exc)})

    yield _ev({"type": "done"})
