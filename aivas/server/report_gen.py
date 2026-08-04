"""HTML vulnerability report generator — WeasyPrint-ready, professional layout."""
from __future__ import annotations

import sqlite3
from datetime import datetime

from aivas.history import get_scan_findings, get_scan_meta
from aivas.server.report_helpers import (
    cve_fix, executive_summary, _GRADE_LABEL, _SEV_ORDER,
)

_ACCENT     = "#0f2744"
_ACCENT_MID = "#1a4a7a"

_SEV_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH":     "#c2550a",
    "MEDIUM":   "#92690a",
    "LOW":      "#166534",
}
_SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#f0fdf4",
}
_GRADE_COLOR = {
    "A": "#166534",
    "B": "#15803d",
    "C": "#92690a",
    "D": "#c2550a",
    "F": "#b91c1c",
}

# Inline SVG — never a broken image in WeasyPrint
_LOGO_SVG = (
    '<svg width="48" height="48" viewBox="0 0 34 34" fill="none" '
    'xmlns="http://www.w3.org/2000/svg">'
    '<path d="M12 27.5 C8.5 29.8 4.5 30 3.6 28.4 C5.5 26.6 7.4 24 8.6 20.8 '
    'L18 3 L26.2 20.5 C27.6 19.4 29.6 19 30.6 19.6 C29.8 21.2 28.2 21.9 27 22 '
    'L29.3 30.2 L13.8 23.8 L26.3 18.4" '
    'stroke="white" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 11pt;
  color: #1e1e2e;
  background: #ffffff;
  line-height: 1.65;
}
/* ---- print overrides ---- */
@media print {
  .no-print { display: none !important; }
}

/* ---- chrome bar (browser only) ---- */
.no-print {
  padding: 10px 20px;
  background: #f1f5f9;
  border-bottom: 1px solid #cbd5e1;
  display: flex;
  gap: 8px;
}
.pbtn {
  font-size: 10pt;
  padding: 6px 16px;
  border: 1px solid #94a3b8;
  background: #ffffff;
  border-radius: 4px;
  cursor: pointer;
  color: #334155;
  text-decoration: none;
  display: inline-block;
}

/* ---- header ---- */
.rpt-header {
  background: #0f2744;
  padding: 26px 40px 22px;
}
.header-logo-cell { vertical-align: middle; padding-right: 16px; }
.header-title-cell { vertical-align: middle; }
.header-title {
  font-size: 20pt;
  font-weight: 700;
  color: #ffffff;
  letter-spacing: -0.2px;
  line-height: 1.1;
}
.header-subtitle {
  font-size: 9pt;
  color: rgba(255,255,255,0.6);
  margin-top: 4px;
  line-height: 1.5;
}
.header-meta-cell { vertical-align: top; text-align: right; }
.header-meta {
  font-family: 'Courier New', Courier, monospace;
  font-size: 9pt;
  color: rgba(255,255,255,0.75);
  line-height: 1.9;
}
.header-meta strong { color: #ffffff; }

/* ---- risk bar ---- */
.risk-bar {
  background: #f8fafc;
  border-bottom: 2px solid #e2e8f0;
  padding: 20px 40px;
}
.grade-cell { vertical-align: middle; padding-right: 24px; }
.grade-badge {
  width: 72px;
  height: 72px;
  border-radius: 10px;
  text-align: center;
  font-size: 34pt;
  font-weight: 800;
  color: #ffffff;
  line-height: 72px;
}
.divider-cell {
  width: 1px;
  background: #cbd5e1;
  padding: 0;
}
.risk-info-cell { vertical-align: middle; padding-left: 24px; }
.risk-label {
  font-size: 14pt;
  font-weight: 700;
  color: #0f2744;
  line-height: 1.2;
}
.risk-sub {
  font-size: 9pt;
  color: #64748b;
  margin-top: 5px;
}
.sev-chip {
  display: inline-block;
  font-family: 'Courier New', Courier, monospace;
  font-size: 8.5pt;
  font-weight: 700;
  padding: 3px 10px;
  border-radius: 12px;
  margin-right: 8px;
  margin-top: 8px;
}

/* ---- body ---- */
.body-content { padding: 30px 40px 44px; }

.section-hdr {
  font-size: 8.5pt;
  font-weight: 700;
  color: #0f2744;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  border-bottom: 2px solid #0f2744;
  padding-bottom: 5px;
  margin-top: 28px;
  margin-bottom: 14px;
}
.first-section { margin-top: 0; }

/* ---- executive summary ---- */
.exec-text {
  font-size: 11pt;
  line-height: 1.7;
  color: #1e293b;
}
.exec-text p { margin-top: 10px; }
.exec-text p:first-child { margin-top: 0; }

/* ---- findings table ---- */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 10pt;
}
.findings-table th {
  font-family: 'Courier New', Courier, monospace;
  font-size: 7.5pt;
  font-weight: 700;
  color: #64748b;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  background: #f8fafc;
  border-bottom: 2px solid #e2e8f0;
  padding: 9px 10px;
  text-align: left;
}
.findings-table td {
  padding: 9px 10px;
  border-bottom: 1px solid #f1f5f9;
  vertical-align: top;
  font-size: 10pt;
}
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:nth-child(even) td { background: #f8fafc; }

.sev-badge {
  font-family: 'Courier New', Courier, monospace;
  font-size: 8pt;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 3px;
  white-space: nowrap;
  display: inline-block;
}
.cve-mono {
  font-family: 'Courier New', Courier, monospace;
  font-size: 9.5pt;
  color: #0f2744;
}
.kev-tag {
  display: inline-block;
  background: #b91c1c;
  color: #ffffff;
  font-family: 'Courier New', Courier, monospace;
  font-size: 7pt;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 2px;
  margin-top: 3px;
}
.cvss-mono {
  font-family: 'Courier New', Courier, monospace;
  font-size: 9.5pt;
  color: #475569;
}
.desc-cell { color: #334155; line-height: 1.5; }
.fix-cell  { color: #334155; line-height: 1.5; }

/* ---- conclusion ---- */
.conclusion-text {
  font-size: 11pt;
  line-height: 1.7;
  color: #1e293b;
}
.conclusion-text p + p { margin-top: 10px; }

/* ---- footer ---- */
.rpt-footer {
  border-top: 1px solid #e2e8f0;
  margin-top: 30px;
  padding-top: 10px;
}
.footer-inner {
  font-family: 'Courier New', Courier, monospace;
  font-size: 8pt;
  color: #94a3b8;
}
.footer-left   { text-align: left; }
.footer-center { text-align: center; color: #b91c1c; font-weight: 700; letter-spacing: 0.12em; }
.footer-right  { text-align: right; }
"""


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _short_fix(text: str) -> str:
    """Return at most 2 complete sentences from a remediation string."""
    import re
    text = text.strip()
    # Split on sentence-ending punctuation followed by whitespace + capital letter
    parts = re.split(r'(?<=[.!?])\s+(?=[A-Z“"])', text)
    return ' '.join(parts[:2]).strip()


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev, "#475569")
    bg    = _SEV_BG.get(sev, "#f8fafc")
    return (
        f'<span class="sev-badge" '
        f'style="color:{color};background:{bg};border:1px solid {color}40">'
        f'{_esc(sev)}</span>'
    )


def _sort_kev_first(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (not f.get("kev"), -(f.get("cvss_score") or 0)))


def _sev_chips_html(findings: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f.get("cvss_severity") == s) for s in _SEV_ORDER}
    parts = []
    for sev in _SEV_ORDER:
        if counts[sev]:
            color = _SEV_COLOR[sev]
            bg    = _SEV_BG[sev]
            parts.append(
                f'<span class="sev-chip" style="color:{color};background:{bg}">'
                f'{counts[sev]}&nbsp;{_esc(sev)}</span>'
            )
    return "".join(parts)


def generate_html_report(conn: sqlite3.Connection, scan_id: int) -> str | None:
    meta = get_scan_meta(conn, scan_id)
    if not meta:
        return None

    findings   = get_scan_findings(conn, scan_id)
    misconfigs = meta.get("misconfigs") or []
    grade  = (meta.get("grade") or "").replace("Grade ", "") or "?"
    score  = int(meta.get("risk_score") or 0)
    target = meta.get("target", "unknown")
    date   = (meta.get("started_at") or "")[:10] or datetime.utcnow().strftime("%Y-%m-%d")
    gc     = _GRADE_COLOR.get(grade, "#475569")

    sorted_f: list[dict] = []
    for sev in _SEV_ORDER:
        sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") == sev]))
    sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") not in _SEV_ORDER]))

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ---- findings rows ----
    finding_rows = ""
    for f in sorted_f:
        sev      = f.get("cvss_severity") or "?"
        desc     = _esc((f.get("description") or "")[:220])
        fix      = _esc(_short_fix(cve_fix(f, conn=conn)))
        cvss     = f.get("cvss_score", "")
        cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else str(cvss or "—")
        kev_html = '<br><span class="kev-tag">&#9888; KEV</span>' if f.get("kev") else ""
        finding_rows += (
            f"<tr>"
            f"<td style='width:80px'>{_sev_badge(sev)}</td>"
            f"<td style='width:130px'><span class='cve-mono'>{_esc(f.get('cve_id',''))}</span>{kev_html}</td>"
            f"<td style='width:44px'><span class='cvss-mono'>{_esc(cvss_str)}</span></td>"
            f"<td><span class='desc-cell'>{desc}</span></td>"
            f"<td style='width:165px'><span class='fix-cell'>{fix}</span></td>"
            f"</tr>\n"
        )

    if not sorted_f:
        finding_rows = (
            '<tr><td colspan="5" style="padding:20px 10px;color:#94a3b8;font-size:10.5pt;text-align:center">'
            'No CVEs matched in the local database — all exposed services appear current.'
            '</td></tr>'
        )

    # ---- misconfig rows ----
    mc_rows = ""
    for mc in misconfigs:
        sev_mc   = (mc.get("severity") or "INFO").upper()
        port_str = f":{mc['port']}" if mc.get("port") else ""
        host_td  = (
            f'<td style="width:150px"><span class="cve-mono">{_esc(mc.get("host",""))}{_esc(port_str)}</span></td>'
            if mc.get("host") else "<td></td>"
        )
        mc_rows += (
            f"<tr>"
            f"<td style='width:80px'>{_sev_badge(sev_mc)}</td>"
            f"<td colspan='3'><span class='desc-cell'>{_esc(mc.get('title',''))}</span></td>"
            f"{host_td}</tr>\n"
        )

    mc_section = ""
    if misconfigs:
        mc_section = f"""
<div class="section-hdr">Section 3 &mdash; Configuration Issues ({len(misconfigs)})</div>
<table class="findings-table">
<thead>
  <tr>
    <th>Severity</th><th colspan="3">Issue</th><th>Host / Port</th>
  </tr>
</thead>
<tbody>{mc_rows}</tbody>
</table>"""

    vuln_sec_num   = 2
    concl_sec_num  = vuln_sec_num + (1 if misconfigs else 0) + 1
    grade_label    = _GRADE_LABEL.get(grade, "")
    sev_chips      = _sev_chips_html(findings)
    no_sev_line    = (
        '<span style="font-size:9pt;color:#94a3b8">No vulnerabilities detected</span>'
        if not sev_chips else sev_chips
    )

    # executive_summary returns HTML (contains <strong>) — do NOT escape it
    exec_html = executive_summary(grade, score, target, findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AIVAS Security Report &mdash; {_esc(target)}</title>
<style>{_CSS}</style>
</head>
<body>

<div class="no-print">
  <button class="pbtn" onclick="window.print()">&#128438;&nbsp;Print / Save PDF</button>
  <a class="pbtn" href="/api/report/{scan_id}/pdf" download="aivas-report-{scan_id}.pdf">&#8595;&nbsp;Download PDF</a>
</div>

<!-- ===== HEADER ===== -->
<div class="rpt-header">
  <table style="width:100%"><tr>
    <td class="header-logo-cell" style="width:64px">{_LOGO_SVG}</td>
    <td class="header-title-cell">
      <div class="header-title">AIVAS</div>
      <div class="header-subtitle">
        Vulnerability Assessment Report &nbsp;&middot;&nbsp;
        AI-Assisted Network Vulnerability Assessment System<br>
        Mbeya University of Science and Technology (MUST)
      </div>
    </td>
    <td class="header-meta-cell">
      <div class="header-meta">
        TARGET &nbsp;<strong>{_esc(target)}</strong><br>
        SCAN DATE &nbsp;<strong>{_esc(date)}</strong><br>
        SCAN ID &nbsp;<strong>#{scan_id}</strong><br>
        GENERATED &nbsp;<strong>{generated}</strong><br>
        ENGINE &nbsp;<strong>Nmap &middot; NIST NVD</strong>
      </div>
    </td>
  </tr></table>
</div>

<!-- ===== RISK BAR ===== -->
<div class="risk-bar">
  <table><tr>
    <td class="grade-cell">
      <div class="grade-badge" style="background:{gc}">{_esc(grade)}</div>
    </td>
    <td class="divider-cell" style="width:1px;padding:0 0;background:#cbd5e1">&nbsp;</td>
    <td class="risk-info-cell">
      <div class="risk-label">Risk Score: {score}/100 &mdash; {_esc(grade_label)}</div>
      <div class="risk-sub">
        {len(findings)} finding{'s' if len(findings) != 1 else ''} &nbsp;&middot;&nbsp;
        {len(misconfigs)} configuration issue{'s' if len(misconfigs) != 1 else ''}
      </div>
      <div style="margin-top:6px">{no_sev_line}</div>
    </td>
  </tr></table>
</div>

<!-- ===== BODY ===== -->
<div class="body-content">

<div class="section-hdr first-section">Section 1 &mdash; Executive Summary</div>
<div class="exec-text">{exec_html}</div>

{mc_section}

<div class="section-hdr">Section {vuln_sec_num} &mdash; Vulnerability Findings ({len(findings)} CVE{'s' if len(findings) != 1 else ''})</div>
<table class="findings-table">
<thead>
  <tr>
    <th>Severity</th>
    <th>CVE ID</th>
    <th>CVSS</th>
    <th>Description</th>
    <th>Remediation</th>
  </tr>
</thead>
<tbody>
{finding_rows}
</tbody>
</table>

<div class="section-hdr">Section {concl_sec_num} &mdash; Conclusion &amp; Next Steps</div>
<div class="conclusion-text">
<p>Remediation must be prioritised by severity level. Critical and High findings require
immediate attention — ideally within 24 to 72 hours of detection. Medium findings should
be addressed within 30 days. Schedule a follow-up scan after applying patches to
verify that identified vulnerabilities have been resolved.</p>
<p>This report was generated automatically from network scan data and correlated against
the local NIST NVD CVE database. Findings should be validated by a qualified security
professional before inclusion in official compliance submissions or audit documentation.</p>
</div>

<div class="rpt-footer">
  <table class="footer-inner" style="width:100%"><tr>
    <td class="footer-left">AIVAS v1.2 &nbsp;&middot;&nbsp; Scan #{scan_id} &nbsp;&middot;&nbsp; MUST</td>
    <td class="footer-center">CONFIDENTIAL</td>
    <td class="footer-right">{datetime.utcnow().year} &nbsp;&middot;&nbsp; {generated}</td>
  </tr></table>
</div>

</div>
</body>
</html>"""
