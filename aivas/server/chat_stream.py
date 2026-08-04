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

import httpx
from groq import Groq
from aivas.narrator.providers.base import BaseProvider
from aivas.tui.agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS
from aivas.history import list_scans as _list_scans
from aivas.server.tool_events import _SILENT_TOOLS, _tool_summary

_MAX_STEPS = 5
_SUMMARIZE_THRESHOLD = 4000
_SUMMARIZE_TOKENS = 500
_XML_CALL_RE = re.compile(r"<function(?:=\w[^>]*)?>.*?</function>", re.DOTALL)


class _Fn:
    __slots__ = ("name", "arguments")
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments

class _TC:
    __slots__ = ("id", "function")
    def __init__(self, tc_id: str, fn: _Fn):
        self.id = tc_id
        self.function = fn

class _Msg:
    __slots__ = ("content", "tool_calls")
    def __init__(self, content: str, tool_calls: list | None):
        self.content = content
        self.tool_calls = tool_calls


def _groq_msg(resp) -> _Msg:
    m = resp.choices[0].message
    tcs = None
    if m.tool_calls:
        tcs = [_TC(tc.id, _Fn(tc.function.name, tc.function.arguments or "{}")) for tc in m.tool_calls]
    return _Msg(m.content or "", tcs)


def _mistral_msg(resp_json: dict) -> _Msg:
    m = resp_json["choices"][0]["message"]
    raw_tcs = m.get("tool_calls") or []
    tcs = None
    if raw_tcs:
        tcs = [_TC(tc["id"], _Fn(tc["function"]["name"], tc["function"].get("arguments") or "{}")) for tc in raw_tcs]
    return _Msg(m.get("content") or "", tcs)

# Short system prompt used only for Phase A (tool routing).
# Keeps per-call token cost low (fits 8b's 20k TPM budget).
# Phase B gets the full _SYSTEM prompt for quality narrative.
_PHASE_A_SYSTEM = (
    "You are a network security tool router. Routing rules:\n\n"
    "NEVER call more than ONE tool per response. If a multi-step task requires "
    "multiple tools, call the first tool only — the next turn handles the next step.\n\n"
    "(0) ALWAYS use Rule 0 (no tools) for: greetings, thanks, explanations, "
    "definitions, questions ABOUT what AIVAS can do, questions about scan types or "
    "techniques, networking questions (subnetting, protocols, terminology), "
    "cybersecurity education questions, or any message that does NOT contain an "
    "explicit instruction to RUN or PERFORM a scan on a specific target. "
    "Examples that ALWAYS trigger Rule 0 (plain text reply, zero tool calls):\n"
    "  - 'how many types of scans can you do?'\n"
    "  - 'what does a port scan do?'\n"
    "  - 'what is nmap?'\n"
    "  - 'explain CVE'\n"
    "  - 'can you scan the gateway?' (asking capability, not commanding a scan)\n"
    "  - 'what scans work on a router?'\n\n"
    "(1) User EXPLICITLY commands a scan on a named target — e.g. 'scan 192.168.1.1', "
    "'check 10.0.0.5 for vulnerabilities', 'run a scan on example.com' → call "
    "scan_host ONCE with that target. Do NOT call get_local_info first.\n"
    "(2) User explicitly asks about the current machine's IP, hostname, or identity — "
    "'my machine', 'my IP', 'local IP', 'what is my IP', 'what is the ip of this device', "
    "'what is this device', 'what network am I on', 'what network is this device in', "
    "'whats my hostname' → call get_local_info.\n"
    "(3a) User says 'scan my machine', 'scan this device', 'scan local machine' → "
    "call get_local_info, then (next turn) call scan_host(target=<primary_ip>).\n"
    "(3b) User says 'scan my network', 'scan the network', 'scan all devices', "
    "'scan the whole network' → call get_local_info, then (next turn) call "
    "scan_host(target=<network>) where <network> is the 'network' field from the "
    "result (e.g. '192.168.1.0/24'). NEVER use primary_ip for a network scan.\n"
    "(4) User wants to see what devices are online (discovery, not a port scan) → "
    "if the user gave an explicit CIDR/range, call discover_hosts(target=<that>). "
    "If no explicit target, call get_local_info first, then (next turn) call "
    "discover_hosts(target=<network>) using the 'network' field. "
    "Never guess a network address.\n"
    "(5) NEVER call the same tool twice in one response. NEVER call scan_host more "
    "than once per response regardless of how many 'levels' or 'types' of scans "
    "the user mentions. One tool call per turn, maximum.\n"
    "(6) User says 'scan via SSH', 'scan as <username>', 'scan with credentials', "
    "'credentialed scan', 'SSH scan', 'log in and scan', provides a username/password, "
    "or says 'scan my Windows machine with WinRM' → call remote_scan ONCE with target, "
    "method='ssh' (or 'winrm' for Windows), username, and password if provided.\n"
    "(7) User asks to look up an IP on Shodan, asks what Shodan knows about a host, "
    "wants 'threat intel' or 'external view' of a public IP → call query_shodan(ip=<IP>). "
    "NEVER call this for RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x) — "
    "tell the user Shodan only indexes public internet-facing hosts.\n"
    "(8) Scan depth — always include the level parameter when calling scan_host or remote_scan:\n"
    "  - 'quick scan', 'fast scan', 'basic scan', or just 'scan' with no qualifier → level='1'\n"
    "  - 'full scan', 'detailed scan', 'full vulnerability scan', 'level 2' → level='2'\n"
    "  - 'deep scan', 'comprehensive scan', 'thorough scan', 'level 3' → level='3'\n"
    "  Default when user just says 'scan' without depth: level='1'.\n"
    "(9) User asks to scan a saved device by name ('scan my Kali machine', "
    "'scan the server I saved') → call list_saved_targets first, then next turn "
    "use returned host and credentials to call remote_scan.\n"
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


def _load_mistral_key() -> str | None:
    try:
        from aivas import config as _cfg
        key = _cfg.load().get("mistral_api_key")
        if key:
            return key
    except Exception:
        pass
    return os.environ.get("MISTRAL_API_KEY") or None


def _mistral_phase_a(messages: list[dict], tools: list[dict], max_tokens: int, api_key: str):
    """Sync Mistral chat-completions call (for asyncio.to_thread)."""
    resp = httpx.post(
        "https://api.mistral.ai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": "mistral-small-latest", "messages": messages,
              "tools": tools, "tool_choice": "auto", "max_tokens": max_tokens},
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


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
    if groq_client is None:
        # Mistral provider: no Groq client available — just truncate
        return text[:_SUMMARIZE_THRESHOLD]
    try:
        resp = await asyncio.to_thread(
            lambda: groq_client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=_SUMMARIZE_TOKENS,
            )
        )
        return resp.choices[0].message.content or text[:_SUMMARIZE_THRESHOLD]
    except Exception:
        return text[:_SUMMARIZE_THRESHOLD]


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
    api_key: str | None = None,
    fallback_mistral_key: str | None = None,
) -> AsyncGenerator[dict, None]:
    """Yield WebSocket events for one user turn.

    Phase A: routes to tools (blocking, reliable).
      - Groq provider: uses llama-3.3-70b-versatile with the provided Groq key.
      - Mistral provider: uses mistral-small-latest Phase A with the provided Mistral key.
    Phase B: provider.stream() delivers the narrative response token-by-token.
    """
    use_mistral_phase_a = provider.name == "mistral"

    if use_mistral_phase_a:
        mistral_key = api_key or _load_mistral_key()
        if not mistral_key:
            yield {"type": "error", "text": "Mistral API key required. Add it in Settings → AI Provider."}
            return
        groq = None
    else:
        groq_key = api_key or _load_groq_key()
        if not groq_key:
            yield {"type": "error", "text": "Groq API key required. Add it in Settings → AI Provider."}
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

    # Track tools that have already produced a result this turn.
    # If Phase A tries to call the same non-scan tool twice, break to Phase B.
    _REPEATABLE_TOOLS = {'scan_host', 'remote_scan', 'discover_hosts'}
    _completed_tools: set[str] = set()

    for _step in range(_MAX_STEPS):
        # Phase A uses a short routing-only system prompt.
        # Append scan context (if any) so the model can make informed tool choices.
        # messages[1:] carries history + user message + any accumulated tool turns.
        phase_a_system = _PHASE_A_SYSTEM + (f"\n\n{ctx}" if ctx else "")
        phase_a_msgs = [{"role": "system", "content": phase_a_system}] + messages[1:]
        try:
            if use_mistral_phase_a:
                raw_m = await asyncio.to_thread(
                    _mistral_phase_a, phase_a_msgs, _TOOLS, 400, mistral_key
                )
                msg = _mistral_msg(raw_m)
            else:
                raw = await asyncio.to_thread(
                    lambda: groq.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=phase_a_msgs,
                        tools=_TOOLS,
                        tool_choice="auto",
                        max_tokens=400,
                    )
                )
                msg = _groq_msg(raw)
        except Exception as exc:
            s = str(exc)
            _log.warning("Phase A %s error: %s", provider.name, exc)
            is_rate = "429" in s or "rate_limit" in s.lower()
            if is_rate and not use_mistral_phase_a:
                # Groq rate-limited — try Mistral fallback (browser key first, then config)
                fallback_key = fallback_mistral_key or _load_mistral_key()
                if fallback_key:
                    try:
                        _log.info("Phase A falling back to Mistral (Groq rate limited)")
                        raw_m = await asyncio.to_thread(
                            _mistral_phase_a, phase_a_msgs, _TOOLS, 400, fallback_key
                        )
                        msg = _mistral_msg(raw_m)
                    except Exception as mexc:
                        _log.error("Mistral Phase A fallback also failed: %s", mexc)
                        yield {"type": "error", "text": "Rate limit reached on all providers. Please wait a moment."}
                        return
                else:
                    yield {"type": "error", "text": "Groq rate limit reached — please wait a moment and try again."}
                    return
            elif is_rate:
                yield {"type": "error", "text": "Mistral rate limit reached — please wait a moment and try again."}
                return
            elif not use_mistral_phase_a and ("400" in s or "tool" in s.lower()):
                # Groq generated a malformed tool call — fall back to Mistral for Phase A
                fallback_key = fallback_mistral_key or _load_mistral_key()
                if fallback_key:
                    try:
                        _log.info("Phase A falling back to Mistral (Groq tool_use_failed)")
                        raw_m = await asyncio.to_thread(
                            _mistral_phase_a, phase_a_msgs, _TOOLS, 400, fallback_key
                        )
                        msg = _mistral_msg(raw_m)
                    except Exception as mexc:
                        _log.warning("Mistral Phase A fallback also failed: %s", mexc)
                        yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                        return
                else:
                    # No Mistral key — last resort: groq without tools for a text answer
                    try:
                        raw = await asyncio.to_thread(
                            lambda: groq.chat.completions.create(
                                model="llama-3.3-70b-versatile",
                                messages=phase_a_msgs,
                                max_tokens=400,
                            )
                        )
                        msg = _groq_msg(raw)
                    except Exception as inner:
                        _log.error("Phase A no-tools retry also failed: %s", inner)
                        yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                        return
            else:
                yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                return

        # If Phase A wants to call a tool that already completed this turn,
        # it's stuck in a loop — break to the exhausted-steps Phase B below.
        if msg.tool_calls:
            repeated = [
                tc.function.name for tc in msg.tool_calls
                if tc.function.name not in _REPEATABLE_TOOLS
                and tc.function.name in _completed_tools
            ]
            if repeated:
                _log.info("Phase A loop detected (repeated: %s) — breaking to Phase B", repeated)
                break

        if not msg.tool_calls:
            # Phase B: stream the final response
            try:
                async for token in provider.stream(messages, max_tokens=1200):
                    clean = _XML_CALL_RE.sub("", token)
                    if clean:
                        full_text += clean
                        yield {"type": "token", "text": clean}
            except Exception as exc:
                _log.error("Phase B stream error: %s", exc)
                err = f"\n\n*Stream interrupted: {type(exc).__name__}. Please try again.*"
                yield {"type": "token", "text": err}
                full_text += err
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
                creds_payload = scan_intent[2] if len(scan_intent) > 2 else None
                yield {
                    "type": "scan_triggered",
                    "target": scan_intent[0],
                    "level": scan_intent[1],
                    **({"creds": creds_payload} if creds_payload else {}),
                }
                scan_triggered_this_step = True
            elif tc.function.name not in _SILENT_TOOLS:
                yield {"type": "tool_result", "name": tc.function.name,
                       "summary": _tool_summary(tc.function.name, result)}

            if len(result) > _SUMMARIZE_THRESHOLD:
                result = await _summarize(result, user_text, groq)

            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)
            _completed_tools.add(tc.function.name)

        if scan_triggered_this_step:
            # Scan is now running; don't make more Groq calls this turn.
            yield {"type": "done", "full_text": "", "turns": turns_to_persist}
            return

    # Exhausted steps — stream whatever the provider gives
    try:
        async for token in provider.stream(messages, max_tokens=1200):
            clean = _XML_CALL_RE.sub("", token)
            if clean:
                full_text += clean
                yield {"type": "token", "text": clean}
    except Exception as exc:
        _log.error("Phase B stream error (exhausted steps): %s", exc)
        err = f"\n\n*Stream interrupted: {type(exc).__name__}. Please try again.*"
        yield {"type": "token", "text": err}
        full_text += err
    turns_to_persist.append({"role": "assistant", "content": full_text})
    yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
