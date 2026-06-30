"""HTML vulnerability report generator — no external dependencies."""
from __future__ import annotations

import sqlite3
from datetime import datetime

from aivas.history import get_scan_findings, get_scan_meta
from aivas.server.report_helpers import (
    cve_fix, executive_summary, sev_summary_rows, _GRADE_LABEL, _SEV_ORDER,
)

_GRADE_COLOR = {"A":"#2a6e2a","B":"#3a7a3a","C":"#8a6a00","D":"#8a4000","F":"#8a0000"}
_SEV_CSS = {"CRITICAL":"sev-c","HIGH":"sev-h","MEDIUM":"sev-m","LOW":"sev-l"}
_PIL_CSS = {"CRITICAL":"pc","HIGH":"ph","MEDIUM":"pm","LOW":"pl"}

_CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;font-size:11pt;color:#1a1a1a;background:#fff;line-height:1.5}
.page{max-width:210mm;margin:0 auto;padding:20mm}
.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1a1a2e;padding-bottom:12px;margin-bottom:18px}
.logo{font-size:18pt;font-weight:700;color:#1a1a2e} .logo-sub{font-size:9pt;color:#555;margin-top:3px} .logo-org{font-size:8pt;color:#888;margin-top:2px}
.meta td{font-size:9pt;padding:2px 0 2px 10px;color:#333;vertical-align:top} .meta td:first-child{font-weight:700;color:#1a1a2e;white-space:nowrap;padding-left:0}
.risk{display:flex;gap:20px;align-items:center;background:#f5f7fa;border:1px solid #dde0e6;border-radius:4px;padding:14px 20px;margin-bottom:18px}
.risk-grade{font-size:54pt;font-weight:900;line-height:1;min-width:75px}
.risk-lbl{font-size:14pt;font-weight:700;color:#1a1a2e} .risk-desc{font-size:9pt;color:#555;margin-top:3px}
.pills{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.pill{font-size:8pt;font-weight:700;padding:2px 8px;border-radius:3px;display:inline-block}
.pc{background:#fde8e8;color:#7b1a1a} .ph{background:#fef0e6;color:#7b3a00} .pm{background:#fef9e6;color:#7b5a00} .pl{background:#e8f5e8;color:#1a5c1a}
.no-print{margin-bottom:14px;display:flex;gap:8px}
.pbtn{font-size:10pt;padding:6px 14px;border:1px solid #aaa;background:#f5f7fa;border-radius:4px;cursor:pointer;color:#333;text-decoration:none;display:inline-block}
.pbtn:hover{background:#e8eaed}
.sec{margin-bottom:22px}
.sec-hdr{font-size:10.5pt;font-weight:700;color:#1a1a2e;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #1a1a2e;padding-bottom:4px;margin-bottom:10px}
p{color:#1a1a1a;line-height:1.7;margin-bottom:8px;font-size:10.5pt}
.info-tbl{border-collapse:collapse;width:100%;font-size:10pt;margin-bottom:4px}
.info-tbl td{padding:5px 10px;border:1px solid #e0e3e8} .info-tbl td:first-child{font-weight:700;background:#f5f7fa;width:150px;color:#1a1a2e}
.findings-tbl{border-collapse:collapse;width:100%;font-size:9pt}
.findings-tbl th{background:#1a1a2e;color:#fff;padding:6px 8px;text-align:left;font-size:8.5pt;font-weight:700}
.findings-tbl td{padding:5px 8px;border-bottom:1px solid #e8eaed;vertical-align:top}
.findings-tbl tr:nth-child(even) td{background:#fafbfc}
.sev{font-weight:700;font-size:8pt;padding:2px 6px;border-radius:3px;display:inline-block;white-space:nowrap}
.sev-c{background:#fde8e8;color:#7b1a1a} .sev-h{background:#fef0e6;color:#7b3a00} .sev-m{background:#fef9e6;color:#7b5a00} .sev-l{background:#e8f5e8;color:#1a5c1a}
code{font-family:'Courier New',monospace;font-size:9pt;color:#1a56db}
.sum-tbl{border-collapse:collapse;width:100%;font-size:10pt}
.sum-tbl th{background:#1a1a2e;color:#fff;padding:6px 10px;text-align:left;font-weight:700;font-size:9pt}
.sum-tbl td{padding:5px 10px;border-bottom:1px solid #e8eaed;vertical-align:top}
.rpt-footer{border-top:1px solid #dde0e6;padding-top:8px;margin-top:16px;font-size:8pt;color:#888;text-align:center}
@media print{.no-print{display:none}}"""


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_html_report(conn: sqlite3.Connection, scan_id: int) -> str | None:
    meta = get_scan_meta(conn, scan_id)
    if not meta:
        return None
    findings = get_scan_findings(conn, scan_id)
    grade = (meta.get("grade") or "").replace("Grade ", "") or "?"
    score = int(meta.get("risk_score") or 0)
    target = meta.get("target", "unknown")
    date = (meta.get("started_at") or "")[:10] or datetime.utcnow().strftime("%Y-%m-%d")
    gc = _GRADE_COLOR.get(grade, "#555")
    by = {s: [f for f in findings if f.get("cvss_severity") == s] for s in _SEV_ORDER}
    pills = "".join(
        f'<span class="pill {_PIL_CSS[s]}">{len(by[s])} {s}</span>'
        for s in _SEV_ORDER if by[s]
    )
    sorted_f = sorted(findings, key=lambda f: f.get("cvss_score") or 0, reverse=True)
    rows = ""
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("cvss_severity") or "?"
        sc = _SEV_CSS.get(sev, "sev-l")
        desc = _esc((f.get("description") or "")[:120])
        fix = _esc(cve_fix(f))
        rows += (f'<tr><td style="text-align:center">{i}</td>'
                 f'<td><span class="sev {sc}">{_esc(sev)}</span></td>'
                 f'<td><code>{_esc(f.get("cve_id",""))}</code></td>'
                 f'<td style="text-align:center">{f.get("cvss_score","N/A")}</td>'
                 f'<td>{desc}</td><td>{fix}</td></tr>\n')
    no_cves = '<tr><td colspan="6" style="color:#666;padding:12px">No CVEs matched in local database.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIVAS Security Report — {_esc(target)}</title>
<style>{_CSS}</style></head>
<body><div class="page">
<div class="no-print">
  <button class="pbtn" onclick="window.print()">Print Report</button>
  <a class="pbtn" href="/api/report/{scan_id}/pdf" download="aivas-report-{scan_id}.pdf">Download PDF</a>
</div>
<div class="hdr">
  <div><div class="logo">AIVAS</div>
  <div class="logo-sub">AI-Assisted Vulnerability Assessment System</div>
  <div class="logo-org">Mbeya University of Science and Technology (MUST)</div></div>
  <table class="meta">
    <tr><td>Target</td><td><code>{_esc(target)}</code></td></tr>
    <tr><td>Scan Date</td><td>{date}</td></tr>
    <tr><td>Scan ID</td><td>#{scan_id}</td></tr>
    <tr><td>Generated</td><td>{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</td></tr>
  </table>
</div>
<div class="risk">
  <div class="risk-grade" style="color:{gc}">{_esc(grade)}</div>
  <div style="width:1px;background:#dde0e6;align-self:stretch"></div>
  <div><div class="risk-lbl">{score}/100 Risk Score</div>
  <div class="risk-desc">{_GRADE_LABEL.get(grade,"")}</div>
  <div class="pills">{pills or '<span style="color:#2a6e2a;font-size:9pt">No CVEs matched</span>'}</div></div>
</div>
<div class="sec"><div class="sec-hdr">1. Executive Summary</div>
<p>{executive_summary(grade, score, target, findings)}</p></div>
<div class="sec"><div class="sec-hdr">2. Scan Parameters</div>
<table class="info-tbl">
  <tr><td>Target Host / Range</td><td>{_esc(target)}</td></tr>
  <tr><td>Scan Date</td><td>{date}</td></tr>
  <tr><td>Total CVE Findings</td><td>{len(findings)}</td></tr>
  <tr><td>Risk Score / Grade</td><td>{score}/100 — Grade {_esc(grade)}</td></tr>
  <tr><td>Critical Findings</td><td>{len(by["CRITICAL"])}</td></tr>
  <tr><td>High Findings</td><td>{len(by["HIGH"])}</td></tr>
</table></div>
<div class="sec"><div class="sec-hdr">3. Vulnerability Findings ({len(findings)} CVE(s))</div>
<table class="findings-tbl">
  <thead><tr><th>#</th><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Description</th><th>Remediation</th></tr></thead>
  <tbody>{rows or no_cves}</tbody>
</table></div>
<div class="sec"><div class="sec-hdr">4. Risk Summary</div>
<table class="sum-tbl">
  <thead><tr><th>Severity</th><th>Count</th><th>Potential Impact</th></tr></thead>
  <tbody>{sev_summary_rows(findings)}</tbody>
</table></div>
<div class="sec"><div class="sec-hdr">5. Conclusion and Next Steps</div>
<p>Remediation must be prioritised by severity. Critical and high findings require immediate
attention — ideally within 24 to 48 hours. Medium findings should be scheduled within 30 days.
After applying patches, rescan using <code>aivas scan {_esc(target)}</code> to verify that
vulnerabilities have been resolved.</p>
<p>This report was generated automatically from open-port data and local CVE database correlation.
Results should be validated by a qualified security professional before inclusion in official
documentation or compliance submissions.</p></div>
<div class="rpt-footer">Generated by AIVAS — AI-Assisted Vulnerability Assessment System
&nbsp;|&nbsp; Mbeya University of Science and Technology (MUST) &nbsp;|&nbsp;
{datetime.utcnow().year}</div>
</div></body></html>"""
