"""HTML vulnerability report generator — no external dependencies."""
from __future__ import annotations

import sqlite3
from datetime import datetime

from aivas.history import get_scan_findings, get_scan_meta
from aivas.server.report_helpers import (
    cve_fix, executive_summary, sev_summary_rows, _GRADE_LABEL, _SEV_ORDER,
)

_GRADE_COLOR = {"A": "#2a6e2a", "B": "#3a7a3a", "C": "#8a6a00", "D": "#8a4000", "F": "#8a0000"}
_SEV_CSS   = {"CRITICAL": "sev-c", "HIGH": "sev-h", "MEDIUM": "sev-m", "LOW": "sev-l"}
_PIL_CSS   = {"CRITICAL": "pc", "HIGH": "ph", "MEDIUM": "pm", "LOW": "pl"}

_ACCENT = "#1a5fb4"

_CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,Helvetica,sans-serif;font-size:11pt;color:#1a1a1a;background:#fff;line-height:1.6}
code,kbd,.mono{font-family:'Fira Code','Cascadia Code','Courier New',monospace;font-size:9.5pt}
.page{max-width:210mm;margin:0 auto;padding:18mm 20mm}
/* Header */
.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid """ + _ACCENT + """;padding-bottom:14px;margin-bottom:20px}
.logo{font-size:20pt;font-weight:800;color:""" + _ACCENT + """;letter-spacing:-.5px}
.logo-sub{font-size:9pt;color:#555;margin-top:3px}
.logo-org{font-size:8pt;color:#888;margin-top:2px}
.meta td{font-family:'Fira Code','Courier New',monospace;font-size:8.5pt;padding:2px 0 2px 12px;color:#333;vertical-align:top}
.meta td:first-child{font-weight:700;color:#444;white-space:nowrap;padding-left:0;font-family:Arial,sans-serif;font-size:8.5pt}
/* Risk bar */
.risk{display:flex;gap:20px;align-items:center;background:#f7f9fc;border:1px solid #d8dfe8;border-left:3px solid """ + _ACCENT + """;border-radius:3px;padding:14px 20px;margin-bottom:22px}
.risk-grade{font-family:'Fira Code','Courier New',monospace;font-size:52pt;font-weight:900;line-height:1;min-width:72px}
.risk-lbl{font-size:13pt;font-weight:700;color:#1a1a1a}
.risk-desc{font-size:9pt;color:#555;margin-top:3px}
.pills{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.pill{font-family:'Fira Code','Courier New',monospace;font-size:8pt;font-weight:600;padding:2px 8px;border-radius:3px;display:inline-block}
.pc{background:#fde8e8;color:#7b1a1a}.ph{background:#fef0e6;color:#7b3a00}.pm{background:#fef9e6;color:#7b5a00}.pl{background:#e8f5e8;color:#1a5c1a}
/* Print button */
.no-print{margin-bottom:16px;display:flex;gap:8px}
.pbtn{font-size:10pt;padding:6px 14px;border:1px solid #aaa;background:#f5f7fa;border-radius:4px;cursor:pointer;color:#333;text-decoration:none;display:inline-block}
.pbtn:hover{background:#e8eaed}
/* Sections */
.sec{margin-bottom:24px}
.sec-hdr{font-size:10pt;font-weight:700;color:""" + _ACCENT + """;text-transform:uppercase;letter-spacing:.06em;border-bottom:2px solid """ + _ACCENT + """;padding-bottom:5px;margin-bottom:12px}
p{color:#1a1a1a;line-height:1.75;margin-bottom:10px;font-size:10.5pt}
/* Info table */
.info-tbl{border-collapse:collapse;width:100%;font-size:10pt;margin-bottom:4px}
.info-tbl td{padding:6px 10px;border:1px solid #e0e3e8}
.info-tbl td:first-child{font-weight:600;background:#f5f7fa;width:170px;color:#333}
.info-tbl td:last-child{font-family:'Fira Code','Courier New',monospace;font-size:9.5pt}
/* Findings table */
.findings-tbl{border-collapse:collapse;width:100%;font-size:9pt}
.findings-tbl th{background:""" + _ACCENT + """;color:#fff;padding:7px 8px;text-align:left;font-size:8.5pt;font-weight:600;letter-spacing:.03em}
.findings-tbl td{padding:6px 8px;border-bottom:1px solid #eaedf2;vertical-align:top}
.findings-tbl tr:nth-child(even) td{background:#f9fafb}
.sev{font-family:'Fira Code','Courier New',monospace;font-weight:700;font-size:8pt;padding:2px 6px;border-radius:3px;display:inline-block;white-space:nowrap}
.sev-c{background:#fde8e8;color:#7b1a1a}.sev-h{background:#fef0e6;color:#7b3a00}.sev-m{background:#fef9e6;color:#7b5a00}.sev-l{background:#e8f5e8;color:#1a5c1a}
/* Summary table */
.sum-tbl{border-collapse:collapse;width:100%;font-size:10pt}
.sum-tbl th{background:""" + _ACCENT + """;color:#fff;padding:7px 10px;text-align:left;font-weight:600;font-size:9pt}
.sum-tbl td{padding:6px 10px;border-bottom:1px solid #eaedf2;vertical-align:top}
/* KEV */
.kev-pill{display:inline-block;background:#7f1d1d;color:#fff;font-family:'Fira Code','Courier New',monospace;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;margin-right:6px;letter-spacing:.5px}
/* Footer */
.rpt-footer{border-top:1px solid #d8dfe8;padding-top:10px;margin-top:20px;font-size:8pt;color:#888;text-align:center;line-height:1.8}
@media print{.no-print{display:none}}"""


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sort_kev_first(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (not f.get("kev"),))


def generate_html_report(conn: sqlite3.Connection, scan_id: int) -> str | None:
    meta = get_scan_meta(conn, scan_id)
    if not meta:
        return None
    findings = get_scan_findings(conn, scan_id)
    grade  = (meta.get("grade") or "").replace("Grade ", "") or "?"
    score  = int(meta.get("risk_score") or 0)
    target = meta.get("target", "unknown")
    date   = (meta.get("started_at") or "")[:10] or datetime.utcnow().strftime("%Y-%m-%d")
    gc     = _GRADE_COLOR.get(grade, "#555")

    by = {s: [f for f in findings if f.get("cvss_severity") == s] for s in _SEV_ORDER}
    pills = "".join(
        f'<span class="pill {_PIL_CSS[s]}">{len(by[s])} {s}</span>'
        for s in _SEV_ORDER if by[s]
    )

    sorted_f = []
    for sev in _SEV_ORDER:
        sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") == sev]))
    sorted_f.extend(_sort_kev_first([f for f in findings if f.get("cvss_severity") not in _SEV_ORDER]))

    rows = ""
    for i, f in enumerate(sorted_f, 1):
        sev      = f.get("cvss_severity") or "?"
        sc       = _SEV_CSS.get(sev, "sev-l")
        desc     = _esc((f.get("description") or "")[:140])
        fix      = _esc(cve_fix(f, conn=conn))
        kev_pill = ('<span class="kev-pill" title="CISA Known Exploited Vulnerability">KEV</span>'
                    if f.get("kev") else "")
        cvss     = f.get("cvss_score", "")
        cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else str(cvss or "—")
        rows += (
            f'<tr>'
            f'<td style="text-align:center;color:#888;font-family:\'Fira Code\',monospace;font-size:8.5pt">{i}</td>'
            f'<td><span class="sev {sc}">{_esc(sev)}</span></td>'
            f'<td style="white-space:nowrap">{kev_pill}<code>{_esc(f.get("cve_id",""))}</code></td>'
            f'<td style="text-align:center;font-family:\'Fira Code\',monospace;font-size:9pt">{cvss_str}</td>'
            f'<td style="color:#444">{desc}</td>'
            f'<td style="color:#333;font-size:8.5pt">{fix}</td>'
            f'</tr>\n'
        )
    no_cves = '<tr><td colspan="6" style="color:#888;padding:14px;font-size:10pt">No CVEs matched in local database.</td></tr>'

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIVAS Security Report — {_esc(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">

<div class="no-print">
  <button class="pbtn" onclick="window.print()">Print / Save PDF</button>
  <a class="pbtn" href="/api/report/{scan_id}/pdf" download="aivas-report-{scan_id}.pdf">Download PDF</a>
</div>

<div class="hdr">
  <div>
    <div class="logo">AIVAS</div>
    <div class="logo-sub">AI-Assisted Vulnerability Assessment System</div>
    <div class="logo-org">Mbeya University of Science and Technology (MUST)</div>
  </div>
  <table class="meta">
    <tr><td>Target</td><td>{_esc(target)}</td></tr>
    <tr><td>Scan Date</td><td>{date}</td></tr>
    <tr><td>Scan ID</td><td>#{scan_id}</td></tr>
    <tr><td>Generated</td><td>{generated}</td></tr>
  </table>
</div>

<div class="risk">
  <div class="risk-grade" style="color:{gc}">{_esc(grade)}</div>
  <div style="width:1px;background:#d8dfe8;align-self:stretch"></div>
  <div>
    <div class="risk-lbl">{score}/100 &mdash; Risk Score</div>
    <div class="risk-desc">{_GRADE_LABEL.get(grade, "")}</div>
    <div class="pills">{pills or '<span style="color:#2a6e2a;font-size:9pt">No CVEs matched</span>'}</div>
  </div>
</div>

<div class="sec">
  <div class="sec-hdr">1. Executive Summary</div>
  <p>{executive_summary(grade, score, target, findings)}</p>
</div>

<div class="sec">
  <div class="sec-hdr">2. Scan Parameters</div>
  <table class="info-tbl">
    <tr><td>Target Host / Range</td><td>{_esc(target)}</td></tr>
    <tr><td>Scan Date</td><td>{date}</td></tr>
    <tr><td>Total CVE Findings</td><td>{len(findings)}</td></tr>
    <tr><td>Risk Score / Grade</td><td>{score}/100 &mdash; Grade {_esc(grade)}</td></tr>
    <tr><td>Critical Findings</td><td>{len(by["CRITICAL"])}</td></tr>
    <tr><td>High Findings</td><td>{len(by["HIGH"])}</td></tr>
  </table>
</div>

<div class="sec">
  <div class="sec-hdr">3. Vulnerability Findings ({len(findings)} CVE{'' if len(findings) == 1 else 's'})</div>
  <table class="findings-tbl">
    <thead>
      <tr><th>#</th><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Description</th><th>Remediation</th></tr>
    </thead>
    <tbody>{rows or no_cves}</tbody>
  </table>
</div>

<div class="sec">
  <div class="sec-hdr">4. Risk Summary by Severity</div>
  <table class="sum-tbl">
    <thead><tr><th>Severity</th><th>Count</th><th>Potential Impact</th></tr></thead>
    <tbody>{sev_summary_rows(findings)}</tbody>
  </table>
</div>

<div class="sec">
  <div class="sec-hdr">5. Conclusion and Next Steps</div>
  <p>Remediation must be prioritised by severity. Critical and High findings require immediate
  attention — ideally within 24 to 48 hours. Medium findings should be scheduled within 30 days.
  After applying patches, rescan using <code>aivas scan {_esc(target)}</code> to verify
  that vulnerabilities have been resolved.</p>
  <p>This report was generated automatically from open-port data and local CVE database
  correlation. Results should be validated by a qualified security professional before
  inclusion in official documentation or compliance submissions.</p>
</div>

<div class="rpt-footer">
  Generated by AIVAS &mdash; AI-Assisted Vulnerability Assessment System<br>
  Mbeya University of Science and Technology (MUST) &nbsp;&middot;&nbsp; {datetime.utcnow().year}
</div>

</div>
</body>
</html>"""
