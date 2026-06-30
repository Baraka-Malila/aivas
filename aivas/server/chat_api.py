"""Wraps the Groq agent for HTTP context — no TUI runtime dependency."""
from __future__ import annotations

import os
import sqlite3
import types

from aivas import config as _config
from aivas.history import list_scans, get_scan_findings


def _build_context(conn: sqlite3.Connection, scan_id: int | None = None) -> str:
    lines: list[str] = []
    scans = list_scans(conn, limit=3)
    if not scans:
        return "No scans performed yet."

    lines.append("Recent scans:")
    for s in scans:
        grade = (s.get("grade") or "").replace("Grade ", "")
        lines.append(f"  · Scan #{s['id']}: {s['target']} — Grade {grade} "
                     f"({s['risk_score']}/100) on {str(s['started_at'])[:10]}")

    # Include full findings for the target scan or the most recent one
    target_id = scan_id or scans[0]["id"]
    findings = get_scan_findings(conn, target_id)
    if findings:
        scan_ref = next((s for s in scans if s["id"] == target_id), scans[0])
        grade = (scan_ref.get("grade") or "").replace("Grade ", "")
        lines.append(
            f"\nFindings from scan #{target_id} ({scan_ref['target']}, Grade {grade}):"
        )
        by_sev: dict[str, list] = {}
        for f in findings:
            sev = f.get("cvss_severity") or "UNKNOWN"
            by_sev.setdefault(sev, []).append(f)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev not in by_sev:
                continue
            lines.append(f"  {sev} ({len(by_sev[sev])}):")
            for f in by_sev[sev][:6]:
                desc = (f.get("description") or "")[:100]
                lines.append(
                    f"    - {f['cve_id']} (CVSS {f.get('cvss_score','N/A')}): {desc}"
                )

    return "\n".join(lines)


async def handle_chat(
    conn: sqlite3.Connection,
    text: str,
    scan_id: int | None = None,
) -> tuple[str, tuple[str, int] | None]:
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY",
            None,
        )
    from aivas.tui.agent import run_agent

    holder = types.SimpleNamespace(conn=conn)
    context = _build_context(conn, scan_id=scan_id)
    try:
        response, scan_intent = await run_agent(holder, text, api_key, context=context)
        return response or "", scan_intent
    except Exception as exc:
        s = str(exc)
        if "401" in s or "invalid_api_key" in s.lower():
            return "API key rejected by Groq. Update: aivas config set api_key KEY", None
        return f"AI error: {exc}", None
