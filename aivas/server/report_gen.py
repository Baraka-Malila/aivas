"""HTML vulnerability report generator — no external dependencies."""
from __future__ import annotations

import sqlite3
from datetime import datetime

from aivas.history import get_scan_findings, get_scan_meta
from aivas.server.report_helpers import (
    cve_fix, executive_summary, _GRADE_LABEL, _SEV_ORDER,
)

_ACCENT = "#1a5fb4"

_SEV_COLOR = {
    "CRITICAL": "#7b1a1a",
    "HIGH":     "#7b3a00",
    "MEDIUM":   "#7b5a00",
    "LOW":      "#1a5c1a",
}

_GRADE_COLOR = {
    "A": "#1a5c1a",
    "B": "#3a7a3a",
    "C": "#7b5a00",
    "D": "#8a4000",
    "F": "#7b1a1a",
}

_CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Helvetica,Arial,sans-serif;font-size:11pt;color:#1a1a1a;background:#fff;line-height:1.6}
code,.mono{font-family:'Fira Code','Cascadia Code','Courier New',monospace;font-size:9.5pt}
.page{max-width:794px;margin:0 auto;padding:56px 60px}
.no-print{margin-bottom:20px;display:flex;gap:8px}
.pbtn{font-size:10pt;padding:6px 14px;border:1px solid #aaa;background:#f5f7fa;border-radius:4px;cursor:pointer;color:#333;text-decoration:none;display:inline-block}
.pbtn:hover{background:#e8eaed}
.sec-hdr{font-family:Helvetica,Arial,sans-serif;font-size:10px;font-weight:700;color:""" + _ACCENT + """;letter-spacing:0.08em;border-bottom:1px solid """ + _ACCENT + """;padding-bottom:4px;margin-bottom:10px;margin-top:22px}
p{font-size:12px;line-height:1.7;margin:0;color:#222222}
.col-hdr{display:flex;font-family:'Fira Code','Courier New',monospace;font-size:8.5px;color:#999999;letter-spacing:0.08em;border-bottom:1px solid #c9ced6;padding-bottom:5px;gap:10px;margin-bottom:0}
.finding-row{display:flex;gap:10px;padding:7px 0;border-bottom:1px solid #eceef2;font-size:10.5px;align-items:baseline}
.mc-row{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid #eceef2;font-size:10.5px;align-items:baseline}
.rpt-footer{border-top:1px solid #e2e5ea;margin-top:28px;padding-top:10px;display:flex;justify-content:space-between;font-family:'Fira Code','Courier New',monospace;font-size:8.5px;color:#999999}
@media print{.no-print{display:none}}"""


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sort_kev_first(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (not f.get("kev"), -(f.get("cvss_score") or 0)))


def _sev_counts_html(findings: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f.get("cvss_severity") == s) for s in _SEV_ORDER}
    parts = []
    for sev in _SEV_ORDER:
        if counts[sev]:
            color = _SEV_COLOR.get(sev, "#555")
            parts.append(
                f'<span style="font-family:\'Fira Code\',monospace;font-size:10px;'
                f'font-weight:600;color:{color}">{counts[sev]} {sev}</span>'
            )
    return "&nbsp;&nbsp;".join(parts)


def generate_html_report(conn: sqlite3.Connection, scan_id: int) -> str | None:
    meta = get_scan_meta(conn, scan_id)
    if not meta:
        return None
    findings = get_scan_findings(conn, scan_id)
    misconfigs = meta.get("misconfigs") or []
    grade   = (meta.get("grade") or "").replace("Grade ", "") or "?"
    score   = int(meta.get("risk_score") or 0)
    target  = meta.get("target", "unknown")
    date    = (meta.get("started_at") or "")[:10] or datetime.utcnow().strftime("%Y-%m-%d")
    gc      = _GRADE_COLOR.get(grade, "#555")

    sorted_f = []
    for sev in _SEV_ORDER:
        sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") == sev]))
    sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") not in _SEV_ORDER]))

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Build finding rows (flex layout, not table)
    finding_rows = ""
    for f in sorted_f:
        sev   = f.get("cvss_severity") or "?"
        sc    = _SEV_COLOR.get(sev, "#555")
        desc  = _esc((f.get("description") or "")[:160])
        fix   = _esc(cve_fix(f, conn=conn))
        cvss  = f.get("cvss_score", "")
        cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else str(cvss or "—")
        kev_html = (
            f'<br><span style="font-family:\'Fira Code\',monospace;font-size:9px;'
            f'font-weight:700;color:#7b1a1a">KEV</span>'
            if f.get("kev") else ""
        )
        finding_rows += (
            f'<div class="finding-row">'
            f'<span style="width:60px;font-family:\'Fira Code\',monospace;font-size:9px;font-weight:700;color:{sc};flex-shrink:0">{_esc(sev)}</span>'
            f'<span style="width:120px;font-family:\'Fira Code\',monospace;font-size:9.5px;color:#111318;flex-shrink:0">{_esc(f.get("cve_id",""))}{kev_html}</span>'
            f'<span style="width:32px;font-family:\'Fira Code\',monospace;font-size:9.5px;flex-shrink:0">{_esc(cvss_str)}</span>'
            f'<span style="flex:1;color:#333333;line-height:1.5">{desc}</span>'
            f'<span style="width:140px;color:#333333;line-height:1.5;font-size:10px">{fix}</span>'
            f'</div>\n'
        )

    no_findings_row = (
        '<div style="padding:14px 0;color:#888;font-size:10.5px">No CVEs matched in local database.</div>'
        if not sorted_f else ""
    )

    # Build misconfig rows
    mc_rows = ""
    for mc in misconfigs:
        sev_mc = (mc.get("severity") or "INFO").upper()
        sc_mc  = _SEV_COLOR.get(sev_mc, "#555")
        host_str = ""
        if mc.get("host"):
            port_str = f":{mc['port']}" if mc.get("port") else ""
            host_str = f'<span style="width:130px;font-family:\'Fira Code\',monospace;font-size:9.5px;color:#666666;flex-shrink:0">{_esc(mc["host"])}{_esc(port_str)}</span>'
        mc_rows += (
            f'<div class="mc-row">'
            f'<span style="width:60px;font-family:\'Fira Code\',monospace;font-size:9px;font-weight:700;color:{sc_mc};flex-shrink:0">{_esc(sev_mc)}</span>'
            f'<span style="flex:1;color:#333333">{_esc(mc.get("title",""))}</span>'
            f'{host_str}'
            f'</div>\n'
        )

    mc_section = ""
    if misconfigs:
        mc_section = f"""
<div class="sec-hdr">2 &middot; CONFIGURATION ISSUES ({len(misconfigs)})</div>
<div class="col-hdr" style="width:60px;display:inline-block;margin-right:10px">SEVERITY</div>
{mc_rows}"""

    findings_num = 2 + (1 if misconfigs else 0)
    summary_num = findings_num + 1
    conclusion_num = summary_num + 1

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIVAS Security Report &mdash; {_esc(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">

<div class="no-print">
  <button class="pbtn" onclick="window.print()">Print / Save PDF</button>
  <a class="pbtn" href="/api/report/{scan_id}/pdf" download="aivas-report-{scan_id}.pdf">Download PDF</a>
</div>

<!-- Header -->
<div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid {_ACCENT};padding-bottom:16px">
  <div style="display:flex;gap:12px;align-items:flex-start">
    <img src="/api/logo.png" alt="AIVAS" style="width:40px;height:40px;object-fit:contain">
    <div>
      <div style="font-size:20px;font-weight:700;color:#111318;letter-spacing:-0.3px">AIVAS Security Report</div>
      <div style="font-size:10px;color:#666666;margin-top:3px">AI-Assisted Network Vulnerability Assessment System</div>
      <div style="font-size:9px;color:#888888;margin-top:2px">Mbeya University of Science and Technology (MUST)</div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:auto auto;gap:3px 12px;font-family:'Fira Code','Courier New',monospace;font-size:9.5px">
    <span style="color:#999999">TARGET</span><span style="color:#111318">{_esc(target)}</span>
    <span style="color:#999999">SCAN DATE</span><span style="color:#111318">{date}</span>
    <span style="color:#999999">SCAN ID</span><span style="color:#111318">#{scan_id}</span>
    <span style="color:#999999">GENERATED</span><span style="color:#111318">{generated}</span>
    <span style="color:#999999">ENGINE</span><span style="color:#111318">Nmap &middot; NIST NVD</span>
  </div>
</div>

<!-- Risk bar -->
<div style="display:flex;gap:24px;align-items:center;border-bottom:1px solid #e2e5ea;padding:18px 0">
  <div style="font-size:56px;font-weight:800;color:{gc};line-height:1;min-width:60px">{_esc(grade)}</div>
  <div style="width:1px;background:#e2e5ea;align-self:stretch"></div>
  <div>
    <div style="font-size:15px;font-weight:700;color:#111318">Risk Score {score}/100 &mdash; {_GRADE_LABEL.get(grade,"")}</div>
    <div style="font-size:10px;color:#666666;margin-top:2px">{_esc(executive_summary(grade, score, target, findings)[:120])}&hellip;</div>
    <div style="display:flex;gap:16px;margin-top:8px">
      {_sev_counts_html(findings)}
    </div>
  </div>
</div>

<!-- Executive Summary -->
<div class="sec-hdr">1 &middot; EXECUTIVE SUMMARY</div>
<p>{_esc(executive_summary(grade, score, target, findings))}</p>

{mc_section}

<!-- Vulnerability Findings -->
<div class="sec-hdr">{findings_num} &middot; VULNERABILITY FINDINGS ({len(findings)} CVE{'s' if len(findings) != 1 else ''})</div>
<div class="col-hdr">
  <span style="width:60px;flex-shrink:0">SEVERITY</span>
  <span style="width:120px;flex-shrink:0">CVE ID</span>
  <span style="width:32px;flex-shrink:0">CVSS</span>
  <span style="flex:1">DESCRIPTION</span>
  <span style="width:140px;flex-shrink:0">REMEDIATION</span>
</div>
{finding_rows or no_findings_row}

<!-- Conclusion -->
<div class="sec-hdr">{conclusion_num} &middot; CONCLUSION AND NEXT STEPS</div>
<p>Remediation must be prioritised by severity. Critical and High findings require immediate
attention. Medium findings should be scheduled within 30 days.
After applying patches, rescan to verify that vulnerabilities have been resolved.</p>
<p style="margin-top:10px">This report was generated automatically from open-port data and local CVE database
correlation. Results should be validated by a qualified security professional before
inclusion in official documentation or compliance submissions.</p>

<!-- Footer -->
<div class="rpt-footer">
  <span>AIVAS v1.2.0 &middot; scan #{scan_id}</span>
  <span style="color:#7b1a1a;font-weight:600;letter-spacing:0.15em">CONFIDENTIAL</span>
  <span>{datetime.utcnow().year} &middot; MUST</span>
</div>

</div>
</body>
</html>"""
