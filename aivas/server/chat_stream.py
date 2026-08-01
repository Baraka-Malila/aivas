"""Streaming agent loop for the web chat WebSocket."""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
from typing import AsyncGenerator

from groq import Groq
from aivas.narrator.providers.base import BaseProvider
from aivas.tui.agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS

_MAX_STEPS = 5
_SUMMARIZE_THRESHOLD = 4000
_SUMMARIZE_TOKENS = 500
_XML_CALL_RE = re.compile(r"<function(?:=\w[^>]*)?>.*?</function>", re.DOTALL)


def _load_groq_key() -> str | None:
    try:
        from aivas import config as _cfg
        key = _cfg.load().get("api_key")
        if key:
            return key
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY") or None


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


def _exec_tool_local(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None
) -> tuple[str, tuple | None]:
    """Dispatch tool call. Returns (result_json, scan_intent | None)."""
    from aivas.tui.agent import _exec_tool
    return _exec_tool(name, args, conn, shodan_key=shodan_key)


async def stream_agent_response(
    provider: BaseProvider,
    session_history: list[dict],
    user_text: str,
    conn: sqlite3.Connection,
    shodan_key: str | None = None,
) -> AsyncGenerator[dict, None]:
    """Yield WebSocket events for one user turn.

    Phase A: Groq llama-3.1-8b-instant handles tool calls (blocking, fast).
    Phase B: provider.stream() delivers the final response token-by-token.
    """
    groq_key = _load_groq_key()
    if not groq_key:
        yield {"type": "error", "text": "No Groq API key configured. Run: aivas config set api_key YOUR_KEY"}
        return

    groq = Groq(api_key=groq_key)
    messages: list[dict] = [{"role": "system", "content": _SYSTEM}]
    if session_history:
        messages.extend(session_history)
    messages.append({"role": "user", "content": user_text})

    turns_to_persist: list[dict] = []
    full_text = ""

    yield {"type": "thinking"}

    for _step in range(_MAX_STEPS):
        try:
            resp = await asyncio.to_thread(
                lambda: groq.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=messages,
                    tools=_TOOLS,
                    tool_choice="auto",
                    max_tokens=600,
                )
            )
        except Exception as exc:
            yield {"type": "error", "text": f"AI error: {exc}"}
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
        tool_calls_payload = [
            {
                "id": tc.id, "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
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

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}

            result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)

            if scan_intent:
                yield {"type": "scan_triggered", "target": scan_intent[0], "level": scan_intent[1]}

            if len(result) > _SUMMARIZE_THRESHOLD:
                result = await _summarize(result, user_text, groq)

            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

    # Exhausted steps — stream whatever the provider gives
    async for token in provider.stream(messages, max_tokens=1200):
        clean = _XML_CALL_RE.sub("", token)
        if clean:
            full_text += clean
            yield {"type": "token", "text": clean}
    turns_to_persist.append({"role": "assistant", "content": full_text})
    yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
