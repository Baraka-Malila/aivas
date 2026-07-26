"""HTTP chat helpers — session-aware multi-turn chat and stateless narration."""
from __future__ import annotations

import os
import sqlite3
import types

from aivas import config as _config
from aivas.history import list_scans, get_scan_findings
from aivas.server.chat_memory import (
    load_history, save_user, save_assistant, save_tool_result,
    update_title_if_unset, touch_session,
)


_HISTORY_TURNS = 6


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
    session_id: str,
    text: str,
    scan_id: int | None = None,
) -> tuple[str, tuple[str, int] | None]:
    """Multi-turn chat. Loads history, calls LLM, persists user + assistant turns."""
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY",
            None,
        )

    history = load_history(conn, session_id, max_turns=_HISTORY_TURNS)
    context = _build_context(conn, scan_id=scan_id)

    save_user(conn, session_id, text)
    update_title_if_unset(conn, session_id, text)

    from aivas.tui.agent import run_agent
    holder = types.SimpleNamespace(conn=conn)
    try:
        response, scan_intent, assistant_turns = await run_agent(
            holder, text, api_key, context=context, history=history,
        )
    except Exception as exc:
        s = str(exc)
        if "401" in s or "invalid_api_key" in s.lower():
            return "API key rejected by Groq. Update: aivas config set api_key KEY", None
        return f"AI error: {exc}", None

    for turn in assistant_turns:
        role = turn.get("role")
        if role == "assistant":
            save_assistant(
                conn, session_id, turn.get("content", ""),
                tool_calls=turn.get("tool_calls"),
            )
        elif role == "tool":
            save_tool_result(
                conn, session_id, turn["tool_call_id"], turn.get("content", ""),
            )

    touch_session(conn, session_id)
    return response or "", scan_intent


async def handle_narrate(conn: sqlite3.Connection, scan_id: int) -> str:
    """Generate a security assessment for a completed scan (stateless single-shot)."""
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY"

    scans = list_scans(conn, limit=5)
    scan_ref = next((s for s in scans if s["id"] == scan_id), None)
    if not scan_ref:
        return f"Scan #{scan_id} not found."

    findings = get_scan_findings(conn, scan_id)
    if not findings:
        return f"No findings for scan #{scan_id}."

    lines = [
        f"Scan #{scan_id}: {scan_ref['target']} — Grade {scan_ref.get('grade','?')} "
        f"({scan_ref.get('risk_score','?')}/100)",
        "",
        "Findings:",
    ]
    for f in findings[:15]:
        lines.append(
            f"  {f['cve_id']} CVSS {f.get('cvss_score','N/A')} ({f.get('cvss_severity','?')}): "
            f"{(f.get('description') or '')[:120]}"
        )
    context = "\n".join(lines)

    prompt = (
        f"{context}\n\nWrite a 3-paragraph professional security assessment. "
        "Paragraph 1: overall risk and grade justification. "
        "Paragraph 2: most critical findings and real-world impact. "
        "Paragraph 3: prioritised remediation actions. "
        "Use **bold** for CVE IDs. Do not initiate a new scan."
    )

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
        )
        return resp.choices[0].message.content or "Assessment could not be generated."
    except Exception as exc:
        return f"Assessment error: {exc}"
