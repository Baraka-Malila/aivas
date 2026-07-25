"""Wraps the Groq agent for HTTP context — no TUI runtime dependency.

Session-aware: loads prior conversation history per session_id and persists
new turns after the LLM call.
"""
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

    # 1. Load history
    history = load_history(conn, session_id, max_turns=_HISTORY_TURNS)

    # 2. Build context (scan summary) — separate from history
    context = _build_context(conn, scan_id=scan_id)

    # 3. Persist the user message BEFORE the LLM call so it survives errors
    save_user(conn, session_id, text)
    update_title_if_unset(conn, session_id, text)

    # 4. Call the agent with full history
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

    # 5. Persist new turns
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
    """Generate a 3-paragraph AI security assessment for a completed scan.

    Stateless single-shot call — does NOT use session history.
    """
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY"
    context = _build_context(conn, scan_id=scan_id)
    prompt = (
        "Write a 3-paragraph professional security assessment for the scan above. "
        "Paragraph 1: overall risk posture and grade justification. "
        "Paragraph 2: most critical findings and their real-world impact. "
        "Paragraph 3: prioritised remediation actions. "
        "Use **bold** for CVE IDs and severity labels. Do not initiate a new scan."
    )
    holder = types.SimpleNamespace(conn=conn)
    try:
        from aivas.tui.agent import run_agent
        response, _intent, _turns = await run_agent(
            holder, prompt, api_key, context=context, history=None,
        )
        return response or "Assessment could not be generated."
    except Exception as exc:
        return f"Assessment error: {exc}"
