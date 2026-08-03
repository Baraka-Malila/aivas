"""Streaming agent loop for the web chat WebSocket."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
from typing import AsyncGenerator

_log = logging.getLogger("aivas.chat")

from groq import Groq
from aivas.narrator.providers.base import BaseProvider
from aivas.tui.agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS
from aivas.history import list_scans as _list_scans
from aivas.server.tool_events import _SILENT_TOOLS, _tool_summary

_MAX_STEPS = 5
_SUMMARIZE_THRESHOLD = 4000
_SUMMARIZE_TOKENS = 500
_XML_CALL_RE = re.compile(r"<function(?:=\w[^>]*)?>.*?</function>", re.DOTALL)

# Short system prompt used only for Phase A (tool routing).
# Keeps per-call token cost low (fits 8b's 20k TPM budget).
# Phase B gets the full _SYSTEM prompt for quality narrative.
_PHASE_A_SYSTEM = (
    "You are a network security tool router. Routing rules:\n"
    "(0) Greetings, thanks, general questions, or conversation not requesting a scan "
    "or network action → respond with NO tool calls. Reply in plain text.\n"
    "(1) User gives an explicit target (IP, hostname, CIDR, or remote host) → call "
    "scan_host directly with that target. Do NOT call get_local_info first.\n"
    "(2) User explicitly says 'my machine', 'my IP', 'local IP', or 'what is my IP' "
    "→ call get_local_info.\n"
    "(3a) User says 'scan my machine', 'scan this device', 'scan local machine' → "
    "call get_local_info, then call scan_host(target=<primary_ip>).\n"
    "(3b) User says 'scan my network', 'scan the network', 'scan all devices', "
    "'scan the whole network' → call get_local_info, then call "
    "scan_host(target=<network>) where <network> is the 'network' field from the "
    "result (e.g. '192.168.1.0/24'). NEVER use primary_ip for a network scan.\n"
    "(4) User wants to see what devices are online (discovery, not a port scan) → "
    "if the user gave an explicit CIDR/range, call discover_hosts(target=<that>). "
    "If no explicit target, call get_local_info first, then call "
    "discover_hosts(target=<network>) using the 'network' field. "
    "Never guess a network address.\n"
    "(5) Complete multi-step tasks without stopping to explain between tool calls."
)


def _load_groq_key() -> str | None:
    try:
        from aivas import config as _cfg
        key = _cfg.load().get("api_key")
        if key:
            return key
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY") or None


def _build_web_context(conn: sqlite3.Connection) -> str:
    scans = _list_scans(conn, limit=3)
    if not scans:
        return ""
    lines = ["Recent scans:"]
    for s in scans:
        lines.append(
            f"  · scan #{s['id']}: {s['target']} — Grade {s.get('grade', '?')}, "
            f"{s.get('finding_count', 0)} findings"
        )
    return "\n".join(lines)


async def _summarize(text: str, question: str, groq_client) -> str:
    prompt = (
        f"Extract only the security-relevant facts needed to answer: {question!r}\n\n"
        f"Tool output:\n{text}"
    )
    resp = await asyncio.to_thread(
        lambda: groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=_SUMMARIZE_TOKENS,
        )
    )
    return resp.choices[0].message.content or text[:_SUMMARIZE_THRESHOLD]


async def _exec_tool_local(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None
) -> tuple[str, tuple | None]:
    """Dispatch tool call. Returns (result_json, scan_intent | None)."""
    from aivas.tui.agent import _exec_tool
    return await _exec_tool(name, args, conn, shodan_key=shodan_key)


_LANG_DIRECTIVES = {
    "auto": (
        "Language rule: respond in ENGLISH by default. "
        "Switch to Swahili ONLY if the user's message clearly contains Swahili words "
        "(e.g., habari, ninataka, asante, karibu, tafadhali, nakushukuru, mtandao). "
        "A message like 'hello', 'hi', 'scan my network', or any English sentence → reply in English only. "
        "NEVER mix languages. NEVER add parenthetical translations like '(Good morning)'. "
        "NEVER write the same sentence in two languages."
    ),
    "en": (
        "Always respond in English. "
        "Do not include any Swahili words, greetings, phrases, or parenthetical translations."
    ),
    "sw": (
        "Always respond in Swahili (Kiswahili). "
        "Do not include any English words, greetings, phrases, or parenthetical translations. "
        "Never write English in parentheses to clarify a Swahili word."
    ),
}


async def stream_agent_response(
    provider: BaseProvider,
    session_history: list[dict],
    user_text: str,
    conn: sqlite3.Connection,
    shodan_key: str | None = None,
    lang: str = "auto",
) -> AsyncGenerator[dict, None]:
    """Yield WebSocket events for one user turn.

    Phase A: Groq llama-3.3-70b-versatile handles tool calls (blocking, fast).
    Phase B: provider.stream() delivers the final response token-by-token.
    """
    groq_key = _load_groq_key()
    if not groq_key:
        yield {"type": "error", "text": "No Groq API key configured. Run: aivas config set api_key YOUR_KEY"}
        return

    groq = Groq(api_key=groq_key)
    ctx = _build_web_context(conn)
    lang_directive = _LANG_DIRECTIVES.get(lang) or _LANG_DIRECTIVES["auto"]
    full_system = "\n\n".join(filter(None, [_SYSTEM, lang_directive, ctx]))
    # messages keeps the full system prompt — used for Phase B (narrative response)
    messages: list[dict] = [{"role": "system", "content": full_system}]
    if session_history:
        messages.extend(session_history)
    messages.append({"role": "user", "content": user_text})

    turns_to_persist: list[dict] = []
    full_text = ""

    yield {"type": "thinking"}

    for _step in range(_MAX_STEPS):
        # Phase A uses a short routing-only system prompt to stay within 8b's TPM budget.
        # Append scan context (if any) so the model can make informed tool choices.
        # messages[1:] carries history + user message + any accumulated tool turns.
        phase_a_system = _PHASE_A_SYSTEM + (f"\n\n{ctx}" if ctx else "")
        phase_a_msgs = [{"role": "system", "content": phase_a_system}] + messages[1:]
        try:
            resp = await asyncio.to_thread(
                lambda: groq.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=phase_a_msgs,
                    tools=_TOOLS,
                    tool_choice="auto",
                    max_tokens=400,
                )
            )
        except Exception as exc:
            s = str(exc)
            if "429" in s or "rate_limit" in s.lower():
                yield {"type": "error", "text": "Groq rate limit reached — please wait a moment and try again."}
                return
            if "400" in s or "tool" in s.lower():
                try:
                    resp = await asyncio.to_thread(
                        lambda: groq.chat.completions.create(
                            model="llama-3.1-8b-instant",
                            messages=phase_a_msgs,
                            max_tokens=400,
                        )
                    )
                except Exception as inner:
                    si = str(inner)
                    if "429" in si or "rate_limit" in si.lower():
                        yield {"type": "error", "text": "Groq rate limit reached — please wait a moment and try again."}
                    else:
                        yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                    return
            else:
                yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                return

        msg = resp.choices[0].message

        if not msg.tool_calls:
            # Phase B: stream the final response
            async for token in provider.stream(messages, max_tokens=1200):
                clean = _XML_CALL_RE.sub("", token)
                if clean:
                    full_text += clean
                    yield {"type": "token", "text": clean}
            turns_to_persist.append({"role": "assistant", "content": full_text})
            yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
            return

        # Handle tool calls
        # Normalize arguments: Groq sometimes sends "null" instead of "{}",
        # which causes a 400 when replayed in the next Phase A call.
        tool_calls_payload = [
            {
                "id": tc.id, "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": (tc.function.arguments or "{}") if (tc.function.arguments or "{}") != "null" else "{}",
                },
            }
            for tc in msg.tool_calls
        ]
        assistant_turn = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tool_calls_payload,
        }
        messages.append(assistant_turn)
        turns_to_persist.append(assistant_turn)

        scan_triggered_this_step = False
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}

            _log.info("tool_call: %s %s", tc.function.name, args)
            if tc.function.name not in _SILENT_TOOLS:
                yield {"type": "tool_call", "name": tc.function.name, "args": args}

            try:
                result, scan_intent = await _exec_tool_local(tc.function.name, args, conn, shodan_key)
            except Exception as exc:
                _log.error("tool_error: %s — %s", tc.function.name, exc)
                result = json.dumps({"error": f"Tool execution failed: {exc}"})
                scan_intent = None

            if scan_intent:
                yield {"type": "scan_triggered", "target": scan_intent[0], "level": scan_intent[1]}
                scan_triggered_this_step = True
            elif tc.function.name not in _SILENT_TOOLS:
                yield {"type": "tool_result", "name": tc.function.name,
                       "summary": _tool_summary(tc.function.name, result)}

            if len(result) > _SUMMARIZE_THRESHOLD:
                result = await _summarize(result, user_text, groq)

            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

        if scan_triggered_this_step:
            # Scan is now running; don't make more Groq calls this turn.
            yield {"type": "done", "full_text": "", "turns": turns_to_persist}
            return

    # Exhausted steps — stream whatever the provider gives
    async for token in provider.stream(messages, max_tokens=1200):
        clean = _XML_CALL_RE.sub("", token)
        if clean:
            full_text += clean
            yield {"type": "token", "text": clean}
    turns_to_persist.append({"role": "assistant", "content": full_text})
    yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
