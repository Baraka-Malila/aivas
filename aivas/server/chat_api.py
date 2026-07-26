"""HTTP chat helpers — stateless narration endpoint."""
from __future__ import annotations

import os
import sqlite3
import uuid

from aivas import config as _config
from aivas.history import list_scans, get_scan_findings
from aivas.narrator.providers.factory import get_provider
from aivas.server.chat_memory import (
    load_history, save_user, save_assistant, save_tool_result,
    update_title_if_unset, touch_session, create_session,
)
from aivas.server.chat_stream import stream_agent_response


async def handle_chat_rest(
    conn: sqlite3.Connection,
    pending: dict,
    session_id: str | None,
    text: str,
) -> dict:
    """REST fallback for POST /api/chat — drives stream_agent_response to completion."""
    sid = session_id or create_session(conn)
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    try:
        provider = get_provider("groq", api_key=api_key)
    except ValueError as exc:
        return {"response": str(exc), "session_id": sid, "scan_id": None}

    history = load_history(conn, sid, max_turns=6)
    full_text = ""
    scan_key = None
    async for event in stream_agent_response(provider, history, text, conn):
        if event["type"] == "token":
            full_text += event["text"]
        elif event["type"] == "scan_triggered":
            scan_key = str(uuid.uuid4())
            pending[scan_key] = (event["target"], event["level"])
        elif event["type"] == "done":
            save_user(conn, sid, text)
            update_title_if_unset(conn, sid, text)
            for turn in event.get("turns", []):
                if turn.get("role") == "assistant":
                    save_assistant(conn, sid, turn.get("content", ""), tool_calls=turn.get("tool_calls"))
                elif turn.get("role") == "tool":
                    save_tool_result(conn, sid, turn["tool_call_id"], turn.get("content", ""))
            touch_session(conn, sid)
    return {"response": full_text, "scan_id": scan_key, "session_id": sid}


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
