"""WebSocket chat endpoint — streams responses to the web UI."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.websocket("/ws/chat/{session_id}")
async def chat_ws(websocket: WebSocket, session_id: str):
    # Lazy import to avoid circular dependency; also lets tests patch main attrs.
    import aivas.server.main as _main

    await websocket.accept()
    if not _main.get_session(_main._conn, session_id):
        await websocket.send_json({"type": "error", "text": "Unknown session id."})
        await websocket.close()
        return
    try:
        while True:
            try:
                msg = await websocket.receive_json()
            except WebSocketDisconnect:
                return
            if msg.get("type") == "interrupt":
                # NOTE (§12.4 — streaming deferred): The LLM call in handle_chat
                # is synchronous and completes before the next receive_json() runs.
                # This acknowledgement is therefore sent AFTER the response is already
                # computed — interrupt has no actual effect today.  Real cancellation
                # requires refactoring handle_chat to stream tokens and check a
                # cancellation flag between chunks.  Do not remove this branch; the
                # frontend expects the "interrupted" reply to keep its state machine
                # consistent even though no in-flight call was cancelled.
                await websocket.send_json({"type": "interrupted"})
                continue
            if msg.get("type") != "user":
                continue
            text = msg.get("text", "")
            try:
                response, scan_intent = await _main.handle_chat(
                    _main._conn, session_id, text,
                )
            except Exception as exc:
                await websocket.send_json({"type": "error", "text": str(exc)})
                continue
            if scan_intent:
                scan_key = str(uuid.uuid4())
                _main._pending[scan_key] = scan_intent
                await websocket.send_json({
                    "type": "scan_intent",
                    "scan_key": scan_key,
                    "target": scan_intent[0],
                    "level": scan_intent[1],
                })
            await websocket.send_json({"type": "complete", "text": response})
    except WebSocketDisconnect:
        return
