"""FastAPI web server for AIVAS — routes, WebSocket scan handler, static SPA serving."""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("aivas.server")

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel

from aivas.database.schema import get_db, create_schema, DB_PATH
from aivas.history import list_scans, get_scan_findings
from aivas.server.auth import (
    register_user, login_user, get_current_user, get_current_user_optional,
    require_admin, list_users,
)
from aivas.server.chat_memory import (
    create_session, get_session, list_sessions, delete_session, load_history,
)
from aivas.server.ws_chat import router as _ws_router
from aivas.server import scheduler_routes as _sched_routes
from aivas.server.scheduler import scheduler_loop

_pending: dict[str, tuple] = {}
_conn: sqlite3.Connection | None = None

_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"
_LEGACY = Path(__file__).parent.parent.parent / "frontend" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _conn
    if _conn is None:
        _conn = get_db(DB_PATH)
        create_schema(_conn)
    _sched_routes.set_conn(_conn)
    _sched_task = asyncio.create_task(scheduler_loop(_conn))
    yield
    _sched_task.cancel()
    try:
        await _sched_task
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan)
app.include_router(_ws_router)
app.include_router(_sched_routes.router)


class AuthRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/stats")
async def stats():
    cve_count = _conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    kev_count = _conn.execute("SELECT COUNT(*) FROM cves WHERE kev=1").fetchone()[0]
    last_sync_row = _conn.execute("SELECT MAX(last_modified_date) FROM cves").fetchone()
    last_sync = (last_sync_row[0] or "")[:10] if last_sync_row and last_sync_row[0] else None
    return {
        "cve_count": cve_count,
        "kev_count": kev_count,
        "last_sync": last_sync,
        "version": "1.2.0",
        "engine": "Nmap · NIST NVD",
    }


@app.post("/api/auth/register")
async def auth_register(body: AuthRequest):
    user = register_user(_conn, body.username, body.password)
    token = login_user(_conn, body.username, body.password)
    return {"token": token, "user": user}


@app.post("/api/auth/login")
async def auth_login(body: AuthRequest):
    token = login_user(_conn, body.username, body.password)
    row = _conn.execute(
        "SELECT id, username, role FROM users WHERE username=?", (body.username,)
    ).fetchone()
    return {"token": token, "user": dict(row)}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return user


@app.get("/api/auth/users")
async def auth_list_users(user: dict = Depends(get_current_user)):
    require_admin(user)
    return list_users(_conn)


@app.get("/api/history")
async def history(limit: int = 10, user: dict | None = Depends(get_current_user_optional)):
    uid = None if (not user or user.get("role") == "admin") else int(user["sub"])
    return list_scans(_conn, limit=limit, user_id=uid)


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    findings = get_scan_findings(_conn, scan_id)
    if not findings and not _conn.execute(
        "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
    ).fetchone():
        raise HTTPException(status_code=404, detail="Scan not found")
    return findings


@app.patch("/api/scan/{scan_id}")
async def rename_scan(scan_id: int, body: dict):
    label = (body.get("label") or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="label is required")
    changes = _conn.execute(
        "UPDATE scans SET label=? WHERE id=?", (label, scan_id)
    ).rowcount
    _conn.commit()
    if not changes:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"id": scan_id, "label": label}


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


@app.get("/api/report/{scan_id}/fix.sh")
async def get_fix_script(scan_id: int):
    from aivas.server.fix_script import generate_fix_script
    script = generate_fix_script(_conn, scan_id)
    if script is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": f"attachment; filename=fix-scan-{scan_id}.sh"},
    )


@app.get("/api/report/{scan_id}/pdf")
async def get_pdf_report(scan_id: int):
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


class AnalyzeRequest(BaseModel):
    type: str  # "risk_summary" | "remediation"
    provider: str = "groq"
    model: str | None = None
    api_key: str | None = None
    lang: str = "auto"


class ScanRequest(BaseModel):
    target: str
    level: int = 2
    creds: dict | None = None


@app.post("/api/analyze/{scan_id}")
async def analyze(scan_id: int, body: AnalyzeRequest):
    from aivas.server.analyze_stream import stream_analysis

    async def _gen():
        async for chunk in stream_analysis(
            _conn, scan_id, body.type,
            body.provider, body.model, body.api_key, body.lang,
        ):
            yield chunk

    return StreamingResponse(_gen(), media_type="application/x-ndjson")


@app.post("/api/chat")
async def chat(body: ChatRequest):
    from aivas.server.chat_api import handle_chat_rest
    return await handle_chat_rest(_conn, _pending, body.session_id, body.text)


@app.get("/api/sessions")
async def list_sessions_route(user: dict | None = Depends(get_current_user_optional)):
    uid = None if (not user or user.get("role") == "admin") else int(user["sub"])
    return list_sessions(_conn, limit=20, user_id=uid)


@app.post("/api/sessions")
async def create_session_route(user: dict | None = Depends(get_current_user_optional)):
    uid = int(user["sub"]) if user else None
    sid = create_session(_conn, user_id=uid)
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


@app.patch("/api/sessions/{session_id}")
async def rename_session_route(session_id: str, body: dict):
    title = (body.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    changes = _conn.execute(
        "UPDATE chat_sessions SET title=? WHERE id=?", (title, session_id)
    ).rowcount
    _conn.commit()
    if not changes:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"id": session_id, "title": title}


@app.delete("/api/sessions/{session_id}")
async def delete_session_route(session_id: str):
    if not delete_session(_conn, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": session_id}


@app.post("/api/scan")
async def start_scan(body: ScanRequest, user: dict | None = Depends(get_current_user_optional)):
    scan_key = str(uuid.uuid4())
    uid = int(user["sub"]) if user else None
    _pending[scan_key] = (body.target, body.level, body.creds, uid)
    return {"scan_key": scan_key}


class ProbeTestRequest(BaseModel):
    method: str
    host: str
    username: str
    password: str = ""
    port: int = 22
    key_path: str | None = None


@app.post("/api/probe/test")
async def probe_test(body: ProbeTestRequest):
    """Test SSH or WinRM credentials without running a scan."""
    from aivas.scanner.probe_errors import CredentialError, ProbeError
    from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
    try:
        if body.method == "ssh":
            from aivas.scanner.ssh_probe import probe_async
            await probe_async(
                host=body.host, username=body.username,
                password=body.password or None, key_path=body.key_path,
                port=body.port, timeout=10,
            )
        else:
            from aivas.scanner.winrm_probe import probe_async
            await probe_async(
                host=body.host, username=body.username,
                password=body.password, port=body.port, timeout=10,
            )
        return {"ok": True}
    except (CredentialError, ProbeConnectionError, ProbeError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": f"Test failed: {exc}"}


class RemoteTargetRequest(BaseModel):
    label: str
    host: str
    method: str = "ssh"
    username: str
    password: str | None = None
    port: int | None = None
    key_path: str | None = None


@app.get("/api/remote-targets")
async def list_remote_targets():
    rows = _conn.execute(
        "SELECT id, label, host, method, username, password, port, key_path, created_at "
        "FROM remote_targets ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/remote-targets")
async def create_remote_target(body: RemoteTargetRequest):
    cur = _conn.execute(
        "INSERT INTO remote_targets (label, host, method, username, password, port, key_path) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (body.label, body.host, body.method, body.username, body.password, body.port, body.key_path),
    )
    _conn.commit()
    row = _conn.execute(
        "SELECT id, label, host, method, username, password, port, key_path, created_at "
        "FROM remote_targets WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return dict(row)


@app.delete("/api/remote-targets/{target_id}")
async def delete_remote_target(target_id: int):
    changes = _conn.execute(
        "DELETE FROM remote_targets WHERE id = ?", (target_id,)
    ).rowcount
    _conn.commit()
    if not changes:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"deleted": target_id}


@app.websocket("/ws/scan/{scan_key}")
async def scan_ws(websocket: WebSocket, scan_key: str):
    await websocket.accept()
    entry = _pending.pop(scan_key, None)
    if not entry:
        await websocket.send_json({"type": "error", "text": "Unknown scan key."})
        await websocket.close()
        return
    target = entry[0]
    level = entry[1]
    creds = entry[2] if len(entry) > 2 else None
    scan_user_id = entry[3] if len(entry) > 3 else None
    _log.info("Scan started: %s (level %d, creds=%s, user=%s)", target, level, bool(creds), scan_user_id)
    from aivas.server.scan_worker import run_scan
    _partial_out: dict = {}
    scan_gen = run_scan(_conn, target, level, creds=creds, _partial_out=_partial_out, user_id=scan_user_id)

    async def _stream():
        async for event in scan_gen:
            if event.get("type") == "error":
                _log.error("Scan error [%s]: %s", target, event.get("text", ""))
            elif event.get("type") == "done":
                _log.info("Scan done: %s — scan_id=%s grade=%s", target,
                          event.get("scan_id"), event.get("grade"))
            await websocket.send_json(event)

    async def _watch_disconnect():
        try:
            data = await websocket.receive_text()
            try:
                if json.loads(data).get("type") == "stop":
                    return "stop"
            except Exception:
                pass
            return "message"
        except (WebSocketDisconnect, Exception):
            return "disconnect"

    stream_task = asyncio.create_task(_stream())
    watch_task = asyncio.create_task(_watch_disconnect())
    try:
        done_set, pending_tasks = await asyncio.wait(
            {stream_task, watch_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending_tasks:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        await scan_gen.aclose()
        if _partial_out:
            try:
                await websocket.send_json({
                    "type": "partial_done",
                    "credential_scan": creds is not None,
                    **_partial_out,
                })
            except Exception:
                pass


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
