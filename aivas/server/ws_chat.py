"""WebSocket chat endpoint — streaming responses to the web UI."""
from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from aivas.server.chat_stream import stream_agent_response
from aivas.server.chat_memory import (
    load_history, save_user, save_assistant, save_tool_result,
    update_title_if_unset, touch_session, get_session,
)
from aivas.narrator.providers.factory import get_provider

router = APIRouter()

_PROVIDER_DEFAULTS = {
    "groq":    "llama-3.3-70b-versatile",
    "mistral": "mistral-small-latest",
    "ollama":  "llama3",
}


@router.websocket("/ws/chat/{session_id}")
async def chat_ws(
    websocket: WebSocket,
    session_id: str,
    provider: str = "groq",
    model: str | None = None,
):
    import aivas.server.main as _main
    from aivas import config as _cfg

    await websocket.accept()
    if not _main.get_session(_main._conn, session_id):
        await websocket.send_json({"type": "error", "text": "Unknown session id."})
        await websocket.close()
        return

    cfg = _cfg.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    mistral_key: str | None = cfg.get("mistral_api_key") or os.environ.get("MISTRAL_API_KEY") or None
    shodan_key: str | None = cfg.get("shodan_key") or os.environ.get("SHODAN_API_KEY") or None
    lang: str = "auto"

    try:
        while True:
            try:
                msg = await websocket.receive_json()
            except WebSocketDisconnect:
                return

            if msg.get("type") == "auth":
                api_key = msg.get("api_key") or api_key
                mistral_key = msg.get("mistral_key") or mistral_key
                shodan_key = msg.get("shodan_key") or shodan_key
                lang = msg.get("lang") or lang
                continue

            if msg.get("type") != "user":
                continue

            text = msg.get("text", "").strip()
            if not text:
                continue

            # Session may have been deleted from History while WebSocket stayed open
            if not get_session(_main._conn, session_id):
                _main._conn.execute(
                    "INSERT OR IGNORE INTO chat_sessions(id, title) VALUES (?, ?)",
                    (session_id, text[:60]),
                )
                _main._conn.commit()

            update_title_if_unset(_main._conn, session_id, text)

            history = load_history(_main._conn, session_id, max_turns=6)

            try:
                chosen_model = model or _PROVIDER_DEFAULTS.get(provider, "llama-3.1-8b-instant")
                llm = get_provider(provider, model=chosen_model, api_key=api_key)
            except ValueError as exc:
                await websocket.send_json({"type": "error", "text": str(exc)})
                continue

            try:
                async for event in stream_agent_response(
                    llm, history, text, _main._conn,
                    shodan_key=shodan_key, lang=lang, api_key=api_key,
                    fallback_mistral_key=mistral_key,
                ):
                    if event["type"] == "scan_triggered":
                        scan_key = str(uuid.uuid4())
                        _main._pending[scan_key] = (event["target"], event["level"], event.get("creds"), None, session_id)
                        await websocket.send_json({**event, "scan_key": scan_key})
                    elif event["type"] == "done":
                        save_user(_main._conn, session_id, text)
                        for turn in event.get("turns", []):
                            role = turn.get("role")
                            if role == "assistant":
                                save_assistant(
                                    _main._conn, session_id, turn.get("content", ""),
                                    tool_calls=turn.get("tool_calls"),
                                )
                            elif role == "tool":
                                save_tool_result(
                                    _main._conn, session_id,
                                    turn["tool_call_id"], turn.get("content", ""),
                                )
                        touch_session(_main._conn, session_id)
                        await websocket.send_json({"type": "done", "text": event.get("full_text", "")})
                    else:
                        await websocket.send_json(event)
            except WebSocketDisconnect:
                return
            except Exception as exc:
                import logging
                logging.getLogger(__name__).error("chat_ws unhandled error: %s", exc, exc_info=True)
                try:
                    await websocket.send_json({"type": "error", "text": f"Server error: {type(exc).__name__}. Please try again."})
                except Exception:
                    pass

    except WebSocketDisconnect:
        return
