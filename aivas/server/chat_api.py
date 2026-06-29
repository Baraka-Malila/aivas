"""Wraps the Groq agent for HTTP context — no TUI runtime dependency."""
from __future__ import annotations

import os
import sqlite3
import types

from aivas import config as _config
from aivas.history import list_scans


def _build_context(conn: sqlite3.Connection) -> str:
    scans = list_scans(conn, limit=3)
    if not scans:
        return "No scans performed yet."
    lines = ["Recent scans:"]
    for s in scans:
        lines.append(f"  · {s['target']} — {s['grade']} ({s['risk_score']}/100)")
    return "\n".join(lines)


async def handle_chat(
    conn: sqlite3.Connection, text: str
) -> tuple[str, tuple[str, int] | None]:
    """Send text to the Groq agent. Returns (response, scan_intent|None).

    scan_intent is (target: str, level: int) when the agent wants to run a scan.
    """
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY",
            None,
        )
    from aivas.tui.agent import run_agent

    holder = types.SimpleNamespace(conn=conn)
    context = _build_context(conn)
    try:
        response, scan_intent = await run_agent(holder, text, api_key, context=context)
        return response or "", scan_intent
    except Exception as exc:
        s = str(exc)
        if "401" in s or "invalid_api_key" in s.lower():
            return "API key rejected by Groq. Update: aivas config set api_key KEY", None
        return f"AI error: {exc}", None
