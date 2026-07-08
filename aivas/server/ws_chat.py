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
