"""FastAPI web server for AIVAS — routes, WebSocket scan handler, static SPA serving."""
from __future__ import annotations

import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from aivas.database.schema import get_db, create_schema, DB_PATH
from aivas.history import list_scans, get_scan_findings
from aivas.server.chat_memory import (
    create_session, get_session, list_sessions, delete_session,
)
from aivas.server.chat_memory import load_history
from aivas.server.chat_api import handle_chat

_pending: dict[str, tuple[str, int]] = {}
_conn: sqlite3.Connection | None = None

_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"
_LEGACY = Path(__file__).parent.parent.parent / "frontend" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _conn
    if _conn is None:
        _conn = get_db(DB_PATH)
        create_schema(_conn)
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/history")
async def history(limit: int = 10):
    return list_scans(_conn, limit=limit)


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    findings = get_scan_findings(_conn, scan_id)
    if not findings and not _conn.execute(
        "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
    ).fetchone():
        raise HTTPException(status_code=404, detail="Scan not found")
    return findings


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int):
    _conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    _conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    _conn.commit()
    return {"deleted": scan_id}


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: int):
    from aivas.server.report_gen import generate_html_report
    html = generate_html_report(_conn, scan_id)
    if html is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return HTMLResponse(html)


@app.get("/api/report/{scan_id}/pdf")
async def get_pdf_report(scan_id: int):
    import asyncio
    from aivas.server.report_pdf import generate_pdf_report
    pdf = await asyncio.to_thread(generate_pdf_report, _conn, scan_id)
    if pdf is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aivas-report-{scan_id}.pdf"},
    )


@app.get("/api/narrate/{scan_id}")
async def narrate(scan_id: int):
    from aivas.server.chat_api import handle_narrate
    text = await handle_narrate(_conn, scan_id)
    return {"response": text}


class ChatRequest(BaseModel):
    text: str
    session_id: str | None = None
    scan_id: int | None = None


class ScanRequest(BaseModel):
    target: str
    level: int = 2


@app.post("/api/chat")
async def chat(body: ChatRequest):
    sid = body.session_id or create_session(_conn)
    response, scan_intent = await handle_chat(
        _conn, sid, body.text, scan_id=body.scan_id,
    )
    scan_key = None
    if scan_intent:
        scan_key = str(uuid.uuid4())
        _pending[scan_key] = scan_intent
    return {"response": response, "scan_id": scan_key, "session_id": sid}


@app.get("/api/sessions")
async def list_sessions_route():
    return list_sessions(_conn, limit=20)


@app.post("/api/sessions")
async def create_session_route():
    sid = create_session(_conn)
    return {"id": sid}


@app.get("/api/sessions/{session_id}")
async def get_session_route(session_id: str):
    s = get_session(_conn, session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    s["messages"] = load_history(_conn, session_id, max_turns=100)
    return s


@app.get("/api/sessions/{session_id}/messages")
async def get_session_messages_route(session_id: str):
    s = get_session(_conn, session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return load_history(_conn, session_id, max_turns=100)


@app.delete("/api/sessions/{session_id}")
async def delete_session_route(session_id: str):
    if not delete_session(_conn, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": session_id}


@app.post("/api/scan")
async def start_scan(body: ScanRequest):
    scan_key = str(uuid.uuid4())
    _pending[scan_key] = (body.target, body.level)
    return {"scan_key": scan_key}


@app.websocket("/ws/scan/{scan_key}")
async def scan_ws(websocket: WebSocket, scan_key: str):
    await websocket.accept()
    entry = _pending.pop(scan_key, None)
    if not entry:
        await websocket.send_json({"type": "error", "text": "Unknown scan key."})
        await websocket.close()
        return
    target, level = entry
    from aivas.server.scan_worker import run_scan
    scan_gen = run_scan(_conn, target, level)
    try:
        async for event in scan_gen:
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        await scan_gen.aclose()


def _serve_spa(path: str = "") -> FileResponse:
    candidate = _DIST / path
    if path and candidate.is_file():
        return FileResponse(str(candidate))
    idx = _DIST / "index.html"
    return FileResponse(str(idx if idx.exists() else _LEGACY))


@app.get("/")
async def index():
    return _serve_spa()


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return _serve_spa(full_path)
