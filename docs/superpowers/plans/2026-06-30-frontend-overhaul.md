# AIVAS Frontend Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-file `frontend/index.html` with a React 18 + Vite + Tailwind CSS application, and extend the FastAPI backend with direct-scan, narrate, and delete endpoints plus granular phase events.

**Architecture:** Backend (`scan_worker.py`) is refactored to emit phase-header events and now wires in the HTTP prober; extracted helpers go to `scan_helpers.py`. Frontend is a React SPA served by FastAPI from `frontend/dist/` after build; during development Vite proxies API calls to the running FastAPI server.

**Tech Stack:** Python / FastAPI / SQLite (existing), React 18, Vite 5, Tailwind CSS 3, Radix UI primitives (same foundation as shadcn/ui — used directly to avoid CLI setup), lucide-react, Vitest + @testing-library/react.

## Global Constraints

- No Python file exceeds 200 lines of code
- No JS/JSX file exceeds 200 lines of code
- Git author on every commit: `Baraka Malila <bmalila87@gmail.com>` — never "Claude"
- Color tokens (exact): sidebar `#0f172a`, surface `#ffffff`, border `#e2e8f0`, accent `#22c55e`
- Severity badge classes: CRITICAL `bg-red-50 text-red-800`, HIGH `bg-amber-50 text-amber-800`, MEDIUM `bg-yellow-50 text-yellow-800`, LOW `bg-green-50 text-green-800`
- Grade colors: A `#2a6e2a`, B `#3a7a3a`, C `#8a6a00`, D `#8a4000`, F `#8a0000`
- Phase header event shape: `{"type":"progress","phase":"phase_header","text":"PHASE NAME"}`
- Done event MUST include `"misconfigs"` key (list of dicts or empty list)
- Scan log lines are NEVER cleared — preserved as collapsible `ScanLog` below results tabs
- Quick Scan = level 1, Scan = level 2 (default)
- All severity label strings: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` (uppercase)
- `autocomplete="off"` on every target input field; no `spellCheck`; no `type="email"`
- Working directory for all frontend commands: `/home/cyberpunk/aivas/frontend`
- Working directory for all Python commands: `/home/cyberpunk/aivas`

---

## Task 1: Backend — scan_helpers.py

Extract CVE-events and per-host helpers from `scan_worker.py` into a new module, and add device-type inference + HTTP probe async generator.

**Files:**
- Create: `aivas/server/scan_helpers.py`
- Test: `tests/server/test_scan_helpers.py`

**Interfaces:**
- Produces:
  - `device_type_from_ports(ports: list[int]) -> str`
  - `cve_events(conn, services, indent) -> AsyncGenerator[dict, None]`  (last item is `{"__findings": [...]}`)
  - `http_probe_events(services) -> AsyncGenerator[dict, None]` (last item is `{"__misconfigs": [...]}`)
  - `scan_host(conn, host_ip, scripts) -> AsyncGenerator[dict, None]` (last item is `{"__svcs":…,"__findings":…,"__misconfigs":…}`)
  - `_ev(phase, text, **extra) -> dict`
  - `_svc_label(svc: dict) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/server/test_scan_helpers.py
import pytest
from aivas.server.scan_helpers import device_type_from_ports


def test_windows_by_rdp():
    assert device_type_from_ports([3389]) == "Windows"


def test_windows_by_smb_rdp():
    assert device_type_from_ports([139, 445, 3389]) == "Windows"


def test_linux_by_ssh_only():
    assert device_type_from_ports([22]) == "Linux"


def test_router_by_telnet_no_ssh():
    assert device_type_from_ports([23, 80]) == "Router"


def test_camera_by_rtsp():
    assert device_type_from_ports([554, 80]) == "Camera"


def test_printer_by_jetdirect():
    assert device_type_from_ports([9100]) == "Printer"


def test_android_adb():
    assert device_type_from_ports([5555]) == "Android"


def test_unknown():
    assert device_type_from_ports([443, 8080]) == "Unknown"
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_scan_helpers.py -v
```

Expected: `ModuleNotFoundError` or `ImportError` — file doesn't exist yet.

- [ ] **Step 3: Create scan_helpers.py**

```python
# aivas/server/scan_helpers.py
"""Per-host scan helpers: CVE event stream, HTTP probe events, device-type inference."""
from __future__ import annotations

import asyncio
import sqlite3
from typing import AsyncGenerator

from aivas.correlator import correlate
from aivas.parser import parse_nmap_xml

_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}

_DEVICE_PATTERNS: list[tuple[set[int], str]] = [
    ({554, 37777}, "Camera"),
    ({9100}, "Printer"),
    ({9100, 515}, "Printer"),
    ({5555}, "Android"),
    ({3389}, "Windows"),
    ({139, 445}, "Windows"),
]


def device_type_from_ports(ports: list[int]) -> str:
    port_set = set(ports)
    for pattern, label in _DEVICE_PATTERNS:
        if pattern & port_set:
            return label
    if 23 in port_set and not port_set & {22, 3389}:
        return "Router"
    if 22 in port_set:
        return "Linux"
    return "Unknown"


def _ev(phase: str, text: str, **extra) -> dict:
    return {"type": "progress", "phase": phase, "text": text, **extra}


def _svc_label(svc: dict) -> str:
    return (
        f"{svc.get('product') or svc.get('service') or 'unknown'} "
        f"{svc.get('version') or ''}"
    ).strip()


async def cve_events(
    conn: sqlite3.Connection,
    services: list[dict],
    indent: str = "  ",
) -> AsyncGenerator[dict, None]:
    """Yield progress events for CVE lookup; last item is {'__findings': [...]}."""
    os_hint = services[0].get("os_family") if services else None
    all_findings: list[dict] = []
    for svc in services:
        yield _ev("cve_lookup", f"{indent}{_svc_label(svc)} (port {svc.get('port','?')})…")
        svc_findings = await asyncio.to_thread(correlate, conn, [svc], os_hint)
        await asyncio.sleep(0.05)
        probable = [f for f in svc_findings if f.get("confidence") in ("probable", "confirmed")]
        if probable:
            worst = max(probable, key=lambda f: f.get("cvss_score") or 0)
            yield _ev(
                "cve_found",
                f"{indent}→ {len(probable)} CVE(s) — worst: "
                f"{worst.get('cve_id','')} ({worst.get('cvss_severity','')} "
                f"{worst.get('cvss_score','')})",
            )
        else:
            yield _ev("cve_none", f"{indent}→ no CVEs matched")
        all_findings.extend(svc_findings)
    yield {"__findings": all_findings}


async def http_probe_events(
    services: list[dict],
) -> AsyncGenerator[dict, None]:
    """Yield HTTP probe progress events; last item is {'__misconfigs': [...]}."""
    from aivas.prober import probe_http_service

    http_svcs = [
        s for s in services
        if s.get("port") in _HTTP_PORTS
        or s.get("service") in ("http", "https", "http-alt")
    ]
    if not http_svcs:
        yield {"__misconfigs": []}
        return

    all_misconfigs: list[dict] = []
    for svc in http_svcs:
        port = svc.get("port", 80)
        host = svc.get("host", "")
        ssl = port == 443 or svc.get("service") == "https"
        label = f"{host}:{port}"
        yield _ev("http_probe", f"  {label} — probing headers, paths, methods…")
        findings = await asyncio.to_thread(probe_http_service, host, port, ssl)
        for f in findings:
            f["host"] = host
            f["port"] = port
            yield _ev("http_finding", f"  {label} — {f['title']} [{f['severity']}]")
        all_misconfigs.extend(findings)
    if not all_misconfigs:
        yield _ev("http_clean", "  No HTTP misconfigurations detected")
    yield {"__misconfigs": all_misconfigs}


async def scan_host(
    conn: sqlite3.Connection, host_ip: str, scripts: str,
    blocking_nmap,
) -> AsyncGenerator[dict, None]:
    """Scan one host; yield events then sentinel with __svcs/__findings/__misconfigs."""
    import asyncio as _a
    fut = _a.ensure_future(_a.to_thread(blocking_nmap, host_ip, scripts, 120))
    start = _a.get_event_loop().time()
    xml: str | None = None
    while True:
        done, _ = await _a.wait({fut}, timeout=3.0)
        if done:
            try:
                xml = fut.result()
            except Exception as exc:
                yield {"type": "error", "text": str(exc)}
                return
            break
        elapsed = int(_a.get_event_loop().time() - start)
        yield _ev("scanning", f"  {host_ip}: scanning… {elapsed}s")
    try:
        services = parse_nmap_xml(xml)
    except Exception as exc:
        yield {"type": "error", "text": f"Parse error {host_ip}: {exc}"}
        return
    if not services:
        yield _ev("host_no_ports", f"  {host_ip}: no open ports found")
        yield {"__svcs": [], "__findings": [], "__misconfigs": []}
        return
    ports = [s.get("port", 0) for s in services]
    dtype = device_type_from_ports(ports)
    yield _ev("host_scan", f"── {host_ip} ({dtype}) ──")
    for svc in services:
        yield _ev(
            "port_open",
            f"    {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
            port=svc.get("port"),
        )
    yield _ev("phase_header", "HTTP PROBE")
    misconfigs: list[dict] = []
    async for ev in http_probe_events(services):
        if "__misconfigs" in ev:
            misconfigs = ev["__misconfigs"]
        else:
            yield ev
    yield _ev("phase_header", "CVE LOOKUP")
    findings: list[dict] = []
    async for ev in cve_events(conn, services, "    "):
        if "__findings" in ev:
            findings = ev["__findings"]
        else:
            yield ev
    yield {"__svcs": services, "__findings": findings, "__misconfigs": misconfigs}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_scan_helpers.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/scan_helpers.py tests/server/test_scan_helpers.py
git commit -m "feat(server): add scan_helpers — device type, HTTP probe events, CVE events"
```

---

## Task 2: Backend — Refactor scan_worker.py

Replace inline helper functions with imports from `scan_helpers`, add phase-header events, and include `misconfigs` in the done event.

**Files:**
- Modify: `aivas/server/scan_worker.py`

**Interfaces:**
- Consumes: `cve_events`, `http_probe_events`, `scan_host`, `_ev`, `_svc_label` from `aivas.server.scan_helpers`
- Produces: unchanged `run_scan(conn, target, level)` generator; done event now includes `"misconfigs": [...]`

- [ ] **Step 1: Confirm existing tests pass before touching anything**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_scan_worker.py -v
```

Expected: all tests PASS.

- [ ] **Step 2: Rewrite scan_worker.py**

Replace the full file contents with the following (189 lines):

```python
# aivas/server/scan_worker.py
"""Scan pipeline orchestrator — nmap + HTTP probe + CVE correlation, yields JSON events."""
from __future__ import annotations

import asyncio
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import AsyncGenerator

from aivas.history import save_scan
from aivas.parser import parse_nmap_xml
from aivas.scanner.nse import scripts_for_level
from aivas.scorer import score_findings
from aivas.server.scan_helpers import (
    _ev, _svc_label,
    cve_events, http_probe_events, scan_host,
)


def _blocking_nmap(target: str, scripts: str, timeout: int = 300) -> str:
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if scripts:
        cmd += ["--script", scripts]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited {result.returncode}: {result.stderr.decode()[:300]}"
        )
    return result.stdout.decode()


def _ping_sweep(target: str, timeout: int = 60) -> list[str]:
    """Return list of live host IPs via nmap -sn ping sweep."""
    nmap_bin = shutil.which("nmap") or "nmap"
    result = subprocess.run(
        [nmap_bin, "-sn", "-oX", "-", target], capture_output=True, timeout=timeout
    )
    if result.returncode != 0:
        return []
    try:
        root = ET.fromstring(result.stdout.decode())
        return [
            h.find("address[@addrtype='ipv4']").get("addr")
            for h in root.findall("host")
            if (
                h.find("status") is not None
                and h.find("status").get("state") == "up"
                and h.find("address[@addrtype='ipv4']") is not None
            )
        ]
    except Exception:
        return []


async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2
) -> AsyncGenerator[dict, None]:
    """Yield granular progress events then a single done or error event."""
    is_net = "/" in target
    scripts = scripts_for_level(level)
    yield _ev("phase_header", "INITIALIZING")
    yield _ev("init", f"Initializing {'network' if is_net else 'host'} scan → {target}")
    all_services: list[dict] = []
    all_findings: list[dict] = []
    all_misconfigs: list[dict] = []

    if is_net:
        yield _ev("phase_header", "HOST DISCOVERY")
        yield _ev("discovery", f"Pinging {target} …")
        live = await asyncio.to_thread(_ping_sweep, target)
        if live:
            yield _ev("hosts_found", f"  ▸ {len(live)} live host(s) found:")
            for h in live:
                yield _ev("host_up", f"    · {h}")
        else:
            yield _ev("hosts_found", "Ping sweep inconclusive — scanning range directly…")
            live = [target]
        for host_ip in live:
            yield _ev("phase_header", "PORT SCANNING")
            async for ev in scan_host(conn, host_ip, scripts, _blocking_nmap):
                if "__svcs" in ev:
                    all_services.extend(ev["__svcs"])
                    all_findings.extend(ev["__findings"])
                    all_misconfigs.extend(ev["__misconfigs"])
                else:
                    yield ev
        if not all_services:
            yield {"type": "error", "text": f"{target}: no open ports found on any live host."}
            return
    else:
        yield _ev("phase_header", "PORT SCANNING")
        yield _ev("ports", "Starting TCP port scan (top 1000 ports)…")
        fut = asyncio.ensure_future(asyncio.to_thread(_blocking_nmap, target, scripts))
        start = asyncio.get_event_loop().time()
        xml: str | None = None
        while True:
            done, _ = await asyncio.wait({fut}, timeout=3.0)
            if done:
                try:
                    xml = fut.result()
                except Exception as exc:
                    yield {"type": "error", "text": str(exc)}
                    return
                break
            elapsed = int(asyncio.get_event_loop().time() - start)
            yield _ev("scanning", f"Port scan running… {elapsed}s elapsed")
        yield _ev("ports_done", "Port scan complete — parsing results")
        try:
            services = parse_nmap_xml(xml)
        except Exception as exc:
            yield {"type": "error", "text": f"Could not parse nmap output: {exc}"}
            return
        if not services:
            yield {
                "type": "error",
                "text": f"{target}: no open ports found — host may be offline or firewalled.",
            }
            return
        yield _ev("open_ports", f"Found {len(services)} open port(s):")
        for svc in services:
            yield _ev(
                "port_open",
                f"  {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
                port=svc.get("port"),
            )
        yield _ev("phase_header", "HTTP PROBE")
        async for ev in http_probe_events(services):
            if "__misconfigs" in ev:
                all_misconfigs = ev["__misconfigs"]
            else:
                yield ev
        yield _ev("phase_header", "CVE LOOKUP")
        async for ev in cve_events(conn, services, "  "):
            if "__findings" in ev:
                all_findings = ev["__findings"]
            else:
                yield ev
        all_services.extend(services)

    yield _ev("phase_header", "SCORING")
    findings = [
        f for f in all_findings if f.get("confidence") in ("probable", "confirmed")
    ][:30]
    yield _ev("scoring", f"Scoring {len(findings)} finding(s)…")
    scored = score_findings(findings)
    grade, score = scored["grade"], scored["score"]
    yield _ev("grade", f"Risk score: {score}/100 — Grade {grade}")
    scan_id = save_scan(conn, target, findings)
    yield {
        "type": "done",
        "target": target,
        "scan_id": scan_id,
        "score": score,
        "grade": grade,
        "service_count": len(all_services),
        "services": [
            {
                "port": s.get("port"),
                "protocol": s.get("protocol", "tcp"),
                "service": s.get("service", ""),
                "product": s.get("product", ""),
                "version": s.get("version", ""),
                "host": s.get("host", ""),
            }
            for s in all_services
        ],
        "findings": [
            {
                "cve_id": f["cve_id"],
                "cvss_score": f.get("cvss_score"),
                "cvss_severity": f.get("cvss_severity"),
                "description": f.get("description") or "",
                "confidence": f.get("confidence"),
                "host": f.get("host", ""),
            }
            for f in findings
        ],
        "misconfigs": all_misconfigs,
    }
```

- [ ] **Step 3: Run existing tests to confirm nothing broke**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_scan_worker.py -v
```

Expected: All tests PASS. The patches `aivas.server.scan_worker._blocking_nmap` and `aivas.server.scan_worker.parse_nmap_xml` still resolve correctly since both remain in scan_worker.py.

- [ ] **Step 4: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/scan_worker.py
git commit -m "refactor(server): scan_worker uses scan_helpers; add phase events, HTTP probe, misconfigs"
```

---

## Task 3: Backend — API additions

Add direct-scan, narrate, and delete endpoints. Update `main.py` to serve the React dist.

**Files:**
- Modify: `aivas/server/chat_api.py`
- Modify: `aivas/server/main.py`
- Test: `tests/server/test_api_additions.py`

**Interfaces:**
- Consumes: `handle_narrate(conn, scan_id)` from `aivas.server.chat_api`
- Produces:
  - `POST /api/scan` body `{target: str, level: int}` → `{scan_key: str}`
  - `GET /api/narrate/{scan_id}` → `{response: str}`
  - `DELETE /api/scan/{scan_id}` → `{deleted: int}`
  - `GET /` serves React dist `index.html` if built, else legacy `index.html`
  - `GET /{full_path:path}` serves static assets from dist or falls back to `index.html`

- [ ] **Step 1: Write the failing test**

```python
# tests/server/test_api_additions.py
import sqlite3
from fastapi.testclient import TestClient
import pytest
from aivas.database.schema import create_schema, get_db
from unittest.mock import patch


@pytest.fixture
def client(tmp_path):
    import aivas.server.main as srv
    db = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    srv._conn = db
    srv._pending = {}
    from fastapi.testclient import TestClient
    return TestClient(srv.app)


def test_post_scan_returns_scan_key(client):
    resp = client.post("/api/scan", json={"target": "10.0.0.1", "level": 1})
    assert resp.status_code == 200
    assert "scan_key" in resp.json()


def test_delete_scan(client):
    import aivas.server.main as srv
    conn = srv._conn
    conn.execute(
        "INSERT INTO scans (target, started_at, finished_at, host_count, finding_count, "
        "risk_score, grade) VALUES (?,?,?,?,?,?,?)",
        ("192.168.1.1", "2026-01-01", "2026-01-01", 1, 0, 0, "Grade A"),
    )
    conn.commit()
    scan_id = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()["id"]
    resp = client.delete(f"/api/scan/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == scan_id
    assert not conn.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_api_additions.py -v
```

Expected: `AttributeError` or 404 — endpoints don't exist yet.

- [ ] **Step 3: Add handle_narrate to chat_api.py**

Append these lines to the bottom of `aivas/server/chat_api.py` (current file is ~75 lines; addition brings it to ~100):

```python


async def handle_narrate(conn: sqlite3.Connection, scan_id: int) -> str:
    """Generate a 3-paragraph AI security assessment for a completed scan."""
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY"
    context = _build_context(conn, scan_id=scan_id)
    prompt = (
        "Write a 3-paragraph professional security assessment for the scan above. "
        "Paragraph 1: overall risk posture and grade justification. "
        "Paragraph 2: most critical findings and their real-world impact. "
        "Paragraph 3: prioritised remediation actions. "
        "Use **bold** for CVE IDs and severity labels. Do not initiate a new scan."
    )
    holder = types.SimpleNamespace(conn=conn)
    try:
        from aivas.tui.agent import run_agent
        response, _ = await run_agent(holder, prompt, api_key, context=context)
        return response or "Assessment could not be generated."
    except Exception as exc:
        return f"Assessment error: {exc}"
```

- [ ] **Step 4: Update main.py**

Replace the full `aivas/server/main.py` with the following:

```python
# aivas/server/main.py
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
    scan_id: int | None = None


class ScanRequest(BaseModel):
    target: str
    level: int = 2


@app.post("/api/chat")
async def chat(body: ChatRequest):
    from aivas.server.chat_api import handle_chat
    response, scan_intent = await handle_chat(_conn, body.text, scan_id=body.scan_id)
    scan_key = None
    if scan_intent:
        scan_key = str(uuid.uuid4())
        _pending[scan_key] = scan_intent
    return {"response": response, "scan_id": scan_key}


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
    """Return dist/index.html if built, else the legacy index.html."""
    candidate = _DIST / path
    if candidate.is_file():
        return FileResponse(str(candidate))
    idx = _DIST / "index.html"
    return FileResponse(str(idx if idx.exists() else _LEGACY))


@app.get("/")
async def index():
    return _serve_spa()


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return _serve_spa(full_path)
```

- [ ] **Step 5: Run tests**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_api_additions.py tests/server/test_scan_worker.py -v
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/chat_api.py aivas/server/main.py tests/server/test_api_additions.py
git commit -m "feat(api): add POST /api/scan, DELETE /api/scan/{id}, GET /api/narrate/{id}; SPA serving"
```

---

## Task 4: Frontend Scaffold

Set up the React + Vite + Tailwind project in `frontend/`.

**Files:**
- Replace: `frontend/index.html` (Vite entry point replacing old single-file app)
- Create: `frontend/package.json`
- Create: `frontend/vite.config.js`
- Create: `frontend/tailwind.config.js`
- Create: `frontend/postcss.config.js`
- Create: `frontend/src/main.jsx`
- Create: `frontend/src/index.css`
- Create: `frontend/src/test-setup.js`

**Interfaces:**
- Produces: `npm run dev` starts Vite dev server; `npm run test:run` runs Vitest; `npm run build` produces `dist/`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "aivas-web",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:run": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "lucide-react": "^0.469.0",
    "clsx": "^2.1.1",
    "tailwind-merge": "^2.6.0",
    "@radix-ui/react-tabs": "^1.1.2",
    "@radix-ui/react-collapsible": "^1.1.2"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.4",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.5.1",
    "tailwindcss": "^3.4.17",
    "vite": "^6.0.7",
    "vitest": "^2.1.8",
    "@testing-library/react": "^16.1.0",
    "@testing-library/user-event": "^14.5.2",
    "@testing-library/jest-dom": "^6.6.3",
    "jsdom": "^25.0.1"
  }
}
```

Save to `/home/cyberpunk/aivas/frontend/package.json`.

- [ ] **Step 2: Create vite.config.js**

```js
// frontend/vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  root: '.',
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
  },
})
```

- [ ] **Step 3: Create tailwind.config.js**

```js
// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"Courier New"', 'Courier', 'monospace'],
      },
    },
  },
  plugins: [],
}
```

- [ ] **Step 4: Create postcss.config.js**

```js
// frontend/postcss.config.js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

- [ ] **Step 5: Replace frontend/index.html (Vite entry)**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AIVAS — Vulnerability Assessment</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
```

- [ ] **Step 6: Create src/index.css**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  background-color: #f8fafc;
  color: #0f172a;
  font-family: Arial, Helvetica, sans-serif;
}
```

- [ ] **Step 7: Create src/test-setup.js**

```js
// frontend/src/test-setup.js
import '@testing-library/jest-dom'
```

- [ ] **Step 8: Create src/main.jsx**

```jsx
// frontend/src/main.jsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
```

- [ ] **Step 9: Create a minimal src/App.jsx placeholder**

```jsx
// frontend/src/App.jsx
import React from 'react'

export default function App() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <p className="text-slate-500 font-mono">AIVAS loading…</p>
    </div>
  )
}
```

- [ ] **Step 10: Install dependencies**

```bash
cd /home/cyberpunk/aivas/frontend
npm install
```

Expected: `node_modules/` created, no errors.

- [ ] **Step 11: Verify test runner works**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: `No test files found` — that's fine, zero tests zero failures.

- [ ] **Step 12: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/package.json frontend/vite.config.js frontend/tailwind.config.js \
        frontend/postcss.config.js frontend/index.html frontend/src/
git commit -m "feat(frontend): React+Vite+Tailwind scaffold; placeholder App"
```

---

## Task 5: Frontend lib — severity.js and mdToHtml.js

Pure utility functions that all components depend on.

**Files:**
- Create: `frontend/src/lib/severity.js`
- Create: `frontend/src/lib/mdToHtml.js`
- Create: `frontend/src/lib/utils.js`
- Test: `frontend/src/lib/severity.test.js`
- Test: `frontend/src/lib/mdToHtml.test.js`

**Interfaces:**
- Produces:
  - `sevClasses(severity: string) -> string` — Tailwind class string for badge
  - `gradeColor(grade: string) -> string` — hex color for grade letter
  - `gradeBadgeClass(grade: string) -> string` — Tailwind classes for sidebar grade chip
  - `mdToHtml(md: string) -> string` — markdown subset to safe HTML string
  - `cn(...inputs) -> string` — clsx + tailwind-merge utility

- [ ] **Step 1: Write the failing tests**

```js
// frontend/src/lib/severity.test.js
import { describe, it, expect } from 'vitest'
import { sevClasses, gradeColor, gradeBadgeClass } from './severity'

describe('sevClasses', () => {
  it('returns red classes for CRITICAL', () => {
    const cls = sevClasses('CRITICAL')
    expect(cls).toContain('bg-red-50')
    expect(cls).toContain('text-red-800')
  })
  it('returns amber classes for HIGH', () => {
    const cls = sevClasses('HIGH')
    expect(cls).toContain('bg-amber-50')
  })
  it('returns green classes for LOW', () => {
    const cls = sevClasses('LOW')
    expect(cls).toContain('bg-green-50')
  })
  it('falls back to LOW for unknown severity', () => {
    expect(sevClasses('UNKNOWN')).toContain('bg-green-50')
  })
})

describe('gradeColor', () => {
  it('returns dark green for A', () => {
    expect(gradeColor('A')).toBe('#2a6e2a')
  })
  it('returns red for F', () => {
    expect(gradeColor('F')).toBe('#8a0000')
  })
})

describe('gradeBadgeClass', () => {
  it('returns green for A', () => {
    expect(gradeBadgeClass('A')).toContain('green')
  })
  it('returns red for F', () => {
    expect(gradeBadgeClass('F')).toContain('red')
  })
})
```

```js
// frontend/src/lib/mdToHtml.test.js
import { describe, it, expect } from 'vitest'
import { mdToHtml } from './mdToHtml'

describe('mdToHtml', () => {
  it('wraps plain text in a paragraph', () => {
    expect(mdToHtml('hello world')).toContain('<p')
    expect(mdToHtml('hello world')).toContain('hello world')
  })
  it('converts **bold** to <strong>', () => {
    expect(mdToHtml('**CVE-2021-1234** is critical')).toContain('<strong>CVE-2021-1234</strong>')
  })
  it('converts bullet lists', () => {
    const html = mdToHtml('- item one\n- item two')
    expect(html).toContain('<ul')
    expect(html).toContain('<li>')
    expect(html).toContain('item one')
  })
  it('escapes HTML entities', () => {
    expect(mdToHtml('<script>alert(1)</script>')).toContain('&lt;script&gt;')
  })
  it('returns empty string for empty input', () => {
    expect(mdToHtml('')).toBe('')
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: `Cannot find module './severity'` errors.

- [ ] **Step 3: Create severity.js**

```js
// frontend/src/lib/severity.js
export const SEV_CONFIG = {
  CRITICAL: { bg: 'bg-red-50', text: 'text-red-800', border: 'border-red-200' },
  HIGH:     { bg: 'bg-amber-50', text: 'text-amber-800', border: 'border-amber-200' },
  MEDIUM:   { bg: 'bg-yellow-50', text: 'text-yellow-800', border: 'border-yellow-200' },
  LOW:      { bg: 'bg-green-50', text: 'text-green-800', border: 'border-green-200' },
}

export function sevClasses(severity) {
  const cfg = SEV_CONFIG[(severity || '').toUpperCase()] || SEV_CONFIG.LOW
  return `${cfg.bg} ${cfg.text} font-semibold text-xs px-2 py-0.5 rounded border ${cfg.border}`
}

export function gradeColor(grade) {
  const map = { A: '#2a6e2a', B: '#3a7a3a', C: '#8a6a00', D: '#8a4000', F: '#8a0000' }
  return map[grade] || '#555'
}

export function gradeBadgeClass(grade) {
  const map = {
    A: 'bg-green-100 text-green-800',
    B: 'bg-green-50 text-green-700',
    C: 'bg-yellow-50 text-yellow-700',
    D: 'bg-orange-50 text-orange-700',
    F: 'bg-red-50 text-red-800',
  }
  return map[grade] || 'bg-slate-100 text-slate-700'
}
```

- [ ] **Step 4: Create mdToHtml.js**

```js
// frontend/src/lib/mdToHtml.js
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function applyInline(line) {
  return esc(line).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
}

export function mdToHtml(md) {
  if (!md) return ''
  const lines = md.split('\n')
  const out = []
  let inList = false
  for (const raw of lines) {
    const line = raw.trim()
    if (!line) {
      if (inList) { out.push('</ul>'); inList = false }
      continue
    }
    if (line.startsWith('- ') || line.startsWith('* ')) {
      if (!inList) { out.push('<ul class="list-disc pl-5 mb-2">'); inList = true }
      out.push(`<li>${applyInline(line.slice(2))}</li>`)
    } else {
      if (inList) { out.push('</ul>'); inList = false }
      out.push(`<p class="mb-2">${applyInline(line)}</p>`)
    }
  }
  if (inList) out.push('</ul>')
  return out.join('\n')
}
```

- [ ] **Step 5: Create utils.js**

```js
// frontend/src/lib/utils.js
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs) {
  return twMerge(clsx(inputs))
}
```

- [ ] **Step 6: Run tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: All 9 tests PASS.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/lib/
git commit -m "feat(frontend): severity, mdToHtml, utils lib with tests"
```

---

## Task 6: Frontend hooks — useHistory.js and useWebSocket.js

The two stateful hooks that manage server interaction.

**Files:**
- Create: `frontend/src/hooks/useHistory.js`
- Create: `frontend/src/hooks/useWebSocket.js`
- Test: `frontend/src/hooks/useWebSocket.test.jsx`

**Interfaces:**
- `useHistory()` returns `{ scans: Array, loading: bool, refresh: fn, deleteScan: fn(id) }`
- `useWebSocket({ onScanComplete })` returns `{ status, progressLines, result, errorMsg, startScan, reset, isScanning, isDone }`
- `status` values: `'idle' | 'scanning' | 'done' | 'error'`

- [ ] **Step 1: Write failing test for useWebSocket state machine**

```jsx
// frontend/src/hooks/useWebSocket.test.jsx
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useWebSocket } from './useWebSocket'

let mockWs
const mockOnScanComplete = vi.fn()

beforeEach(() => {
  mockWs = {
    onmessage: null,
    onerror: null,
    close: vi.fn(),
  }
  vi.stubGlobal('WebSocket', vi.fn(() => mockWs))
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ json: () => Promise.resolve({ scan_key: 'test-key-123' }) })
  ))
})

describe('useWebSocket', () => {
  it('starts in idle state', () => {
    const { result } = renderHook(() => useWebSocket({}))
    expect(result.current.status).toBe('idle')
    expect(result.current.isScanning).toBe(false)
  })

  it('transitions to scanning on startScan', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    expect(result.current.status).toBe('scanning')
    expect(result.current.isScanning).toBe(true)
  })

  it('transitions to done on done event', async () => {
    const { result } = renderHook(() => useWebSocket({ onScanComplete: mockOnScanComplete }))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'done', scan_id: 5, score: 80, grade: 'B' }) })
    })
    expect(result.current.status).toBe('done')
    expect(result.current.isDone).toBe(true)
    expect(result.current.result.scan_id).toBe(5)
    expect(mockOnScanComplete).toHaveBeenCalled()
  })

  it('accumulates progress lines', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'progress', phase: 'init', text: 'Starting…' }) })
      mockWs.onmessage({ data: JSON.stringify({ type: 'progress', phase: 'phase_header', text: 'PORT SCANNING' }) })
    })
    expect(result.current.progressLines).toHaveLength(2)
  })

  it('transitions to error state on error event', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'error', text: 'nmap not found' }) })
    })
    expect(result.current.status).toBe('error')
    expect(result.current.errorMsg).toBe('nmap not found')
  })

  it('resets to idle on reset()', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => { result.current.reset() })
    expect(result.current.status).toBe('idle')
    expect(result.current.progressLines).toHaveLength(0)
  })
})
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: `Cannot find module './useWebSocket'`.

- [ ] **Step 3: Create useHistory.js**

```js
// frontend/src/hooks/useHistory.js
import { useState, useEffect, useCallback } from 'react'

export function useHistory() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetch('/api/history?limit=20').then(r => r.json())
      setScans(Array.isArray(data) ? data : [])
    } catch {
      setScans([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const deleteScan = useCallback(async (id) => {
    try {
      await fetch(`/api/scan/${id}`, { method: 'DELETE' })
      setScans(prev => prev.filter(s => s.id !== id))
    } catch { /* noop */ }
  }, [])

  return { scans, loading, refresh, deleteScan }
}
```

- [ ] **Step 4: Create useWebSocket.js**

```js
// frontend/src/hooks/useWebSocket.js
import { useState, useCallback, useRef } from 'react'

export function useWebSocket({ onScanComplete } = {}) {
  const [status, setStatus] = useState('idle')
  const [progressLines, setProgressLines] = useState([])
  const [result, setResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const wsRef = useRef(null)

  const startScan = useCallback(async (target, level) => {
    if (status === 'scanning') return
    setStatus('scanning')
    setProgressLines([])
    setResult(null)
    setErrorMsg('')

    let scanKey
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, level }),
      })
      scanKey = (await res.json()).scan_key
    } catch (e) {
      setStatus('error')
      setErrorMsg('Failed to start scan: ' + e.message)
      return
    }

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws/scan/${scanKey}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      const ev = JSON.parse(e.data)
      if (ev.type === 'done') {
        setResult(ev)
        setStatus('done')
        onScanComplete?.()
        ws.close()
      } else if (ev.type === 'error') {
        setErrorMsg(ev.text || 'Scan error')
        setStatus('error')
        ws.close()
      } else if (ev.type === 'progress') {
        setProgressLines(prev => [...prev, ev])
      }
    }
    ws.onerror = () => {
      setErrorMsg('WebSocket connection failed')
      setStatus('error')
    }
  }, [status, onScanComplete])

  const reset = useCallback(() => {
    wsRef.current?.close()
    setStatus('idle')
    setProgressLines([])
    setResult(null)
    setErrorMsg('')
  }, [])

  return {
    status,
    progressLines,
    result,
    errorMsg,
    startScan,
    reset,
    isScanning: status === 'scanning',
    isDone: status === 'done',
  }
}
```

- [ ] **Step 5: Run tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: All hook tests PASS (5 tests in useWebSocket.test.jsx + 9 lib tests = 14 total).

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/hooks/
git commit -m "feat(frontend): useHistory and useWebSocket hooks with state-machine tests"
```

---

## Task 7: Frontend Sidebar.jsx

Fixed left navigation panel showing scan history with grade badges and delete controls.

**Files:**
- Create: `frontend/src/components/Sidebar.jsx`

**Interfaces:**
- Consumes: `gradeBadgeClass` from `../lib/severity`; `lucide-react` icons
- Props: `{ scans, onNewScan, onSelectScan, onDeleteScan, onSettings, activeScanId }`
- `scans` shape: `[{ id, target, started_at, grade, risk_score }]`

- [ ] **Step 1: Create Sidebar.jsx**

```jsx
// frontend/src/components/Sidebar.jsx
import React from 'react'
import { PlusCircle, Settings, Trash2, Shield } from 'lucide-react'
import { gradeBadgeClass } from '../lib/severity'

export default function Sidebar({ scans, onNewScan, onSelectScan, onDeleteScan, onSettings, activeScanId }) {
  return (
    <div className="w-[220px] min-h-screen bg-[#0f172a] flex flex-col text-[#cbd5e1] shrink-0">
      <div className="px-4 pt-5 pb-4 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Shield size={18} className="text-green-400" />
          <span className="font-bold text-white text-lg tracking-tight">AIVAS</span>
        </div>
        <div className="text-xs text-slate-500 mt-1">Vulnerability Assessment</div>
      </div>

      <div className="px-3 py-3">
        <button
          onClick={onNewScan}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          <PlusCircle size={13} />
          New Scan
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3 pb-2">
        {scans.length > 0 && (
          <div className="text-xs text-slate-500 uppercase tracking-wider px-2 mb-2 mt-1">
            Recent Scans
          </div>
        )}
        {scans.length === 0 && (
          <p className="text-slate-600 text-xs px-2 py-3">No scans yet</p>
        )}
        {scans.map(scan => {
          const grade = (scan.grade || '').replace('Grade ', '')
          const isActive = scan.id === activeScanId
          return (
            <div
              key={scan.id}
              role="button"
              tabIndex={0}
              className={`group flex items-center justify-between px-2 py-2 rounded-md cursor-pointer mb-0.5 transition-colors ${
                isActive ? 'bg-[#1e293b] border-l-2 border-blue-500 pl-1.5' : 'hover:bg-[#1e293b]'
              }`}
              onClick={() => onSelectScan(scan)}
              onKeyDown={e => e.key === 'Enter' && onSelectScan(scan)}
            >
              <div className="min-w-0 flex-1">
                <div className="text-sm text-slate-200 truncate">{scan.target}</div>
                <div className="text-xs text-slate-500">{(scan.started_at || '').slice(0, 10)}</div>
              </div>
              <div className="flex items-center gap-1 shrink-0 ml-1">
                <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${gradeBadgeClass(grade)}`}>
                  {grade || '?'}
                </span>
                <button
                  onClick={e => { e.stopPropagation(); onDeleteScan(scan.id) }}
                  className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition-opacity p-0.5 rounded"
                  aria-label="Delete scan"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>
          )
        })}
      </div>

      <div className="px-3 py-3 border-t border-slate-700">
        <button
          onClick={onSettings}
          className="flex items-center gap-2 px-3 py-2 w-full rounded-md hover:bg-[#1e293b] text-slate-400 text-sm transition-colors"
        >
          <Settings size={13} />
          Settings
        </button>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Verify it imports cleanly**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: same 14 tests pass (no regressions).

- [ ] **Step 3: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/Sidebar.jsx
git commit -m "feat(frontend): Sidebar with history list, grade badges, delete"
```

---

## Task 8: Frontend ScanBar.jsx

Sticky top bar with target input, Quick Scan/Scan buttons, and collapsible Advanced Options.

**Files:**
- Create: `frontend/src/components/ScanBar.jsx`

**Interfaces:**
- Props: `{ onScan: fn(target: string, level: number), isScanning: bool }`
- `onScan(target, level)` — called when user clicks either scan button or presses Enter

- [ ] **Step 1: Create ScanBar.jsx**

```jsx
// frontend/src/components/ScanBar.jsx
import React, { useState } from 'react'
import { Search, Zap, ChevronDown, ChevronUp, Loader2 } from 'lucide-react'

export default function ScanBar({ onScan, isScanning }) {
  const [target, setTarget] = useState('')
  const [showOptions, setShowOptions] = useState(false)

  const trigger = (level) => {
    const t = target.trim()
    if (!t || isScanning) return
    onScan(t, level)
  }

  return (
    <div className="bg-white border-b border-slate-200 sticky top-0 z-10 shadow-sm">
      <div className="flex items-center gap-2 px-4 py-3">
        <div className="flex-1 relative">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && trigger(2)}
            placeholder="Target: 192.168.1.1 or 10.0.0.0/24"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            data-form-type="other"
            className="w-full pl-8 pr-3 py-2 text-sm border border-slate-200 rounded-md font-mono bg-slate-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-60"
            disabled={isScanning}
          />
        </div>

        <button
          onClick={() => trigger(1)}
          disabled={!target.trim() || isScanning}
          className="px-3 py-2 text-sm border border-slate-200 rounded-md hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed text-slate-600 whitespace-nowrap flex items-center gap-1.5"
        >
          <Zap size={12} />
          Quick Scan
        </button>

        <button
          onClick={() => trigger(2)}
          disabled={!target.trim() || isScanning}
          className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-md font-medium whitespace-nowrap flex items-center gap-1.5"
        >
          {isScanning ? (
            <><Loader2 size={13} className="animate-spin" /> Scanning…</>
          ) : (
            'Scan'
          )}
        </button>

        <button
          onClick={() => setShowOptions(s => !s)}
          className="px-2 py-2 text-sm border border-slate-200 rounded-md hover:bg-slate-50 text-slate-400"
          aria-label="Toggle advanced options"
        >
          {showOptions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {showOptions && (
        <div className="px-4 pb-3 flex items-center gap-6 text-sm text-slate-500 border-t border-slate-100 pt-2">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" className="rounded accent-blue-600" />
            <span>UDP scan</span>
            <span className="text-slate-400 text-xs">(requires root, slow)</span>
          </label>
          <label className="flex items-center gap-2">
            <span>NSE depth:</span>
            <select className="border border-slate-200 rounded px-2 py-1 text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500">
              <option value="standard">Standard</option>
              <option value="extended">Extended (shellshock, MS17-010…)</option>
            </select>
          </label>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Verify no regressions**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: 14 tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/ScanBar.jsx
git commit -m "feat(frontend): ScanBar with target input, scan levels, advanced options"
```

---

## Task 9: Frontend ProgressFeed.jsx

Live terminal log with phase-header dividers and 80ms staggered line animation.

**Files:**
- Create: `frontend/src/components/ProgressFeed.jsx`

**Interfaces:**
- Props: `{ lines: Array<{type, phase, text}> }`
- Phase-header events (`phase === 'phase_header'`) render as section dividers
- Lines fade in with 80ms stagger (one new line becomes visible every 80ms)

- [ ] **Step 1: Create ProgressFeed.jsx**

```jsx
// frontend/src/components/ProgressFeed.jsx
import React, { useEffect, useRef, useState } from 'react'
import { sevClasses } from '../lib/severity'

const SEV_RE = /\[(CRITICAL|HIGH|MEDIUM|LOW)\]/

function PhaseHeader({ text }) {
  return (
    <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest border-b border-slate-100 pb-1 mt-4 mb-1.5 first:mt-0 select-none">
      — {text} —
    </div>
  )
}

function ProgressLine({ ev }) {
  const match = SEV_RE.exec(ev.text || '')
  const lineClass =
    ev.phase === 'cve_found'
      ? 'text-blue-700'
      : ev.phase === 'cve_none'
      ? 'text-slate-400'
      : ev.phase === 'http_finding'
      ? 'text-amber-700'
      : 'text-slate-700'
  return (
    <div className="font-mono text-sm leading-5">
      {match ? (
        <>
          <span className={lineClass}>{(ev.text || '').replace(SEV_RE, '').trimEnd()} </span>
          <span className={sevClasses(match[1])}>{match[1]}</span>
        </>
      ) : (
        <span className={lineClass}>{ev.text}</span>
      )}
    </div>
  )
}

export default function ProgressFeed({ lines }) {
  const bottomRef = useRef(null)
  const [visible, setVisible] = useState(0)

  useEffect(() => {
    if (lines.length > visible) {
      const t = setTimeout(() => setVisible(v => v + 1), 80)
      return () => clearTimeout(t)
    }
  }, [lines.length, visible])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [visible])

  if (!lines.length) return null

  return (
    <div className="p-4 space-y-0.5 min-h-[80px]">
      {lines.slice(0, visible).map((ev, i) =>
        ev.phase === 'phase_header' ? (
          <PhaseHeader key={i} text={ev.text} />
        ) : (
          <ProgressLine key={i} ev={ev} />
        )
      )}
      <div ref={bottomRef} />
    </div>
  )
}
```

- [ ] **Step 2: Verify no regressions**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: 14 tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/ProgressFeed.jsx
git commit -m "feat(frontend): ProgressFeed with phase headers and staggered 80ms animation"
```

---

## Task 10: Frontend FindingsTable.jsx and MisconfigTable.jsx

The two data tables shown in the Findings tab.

**Files:**
- Create: `frontend/src/components/FindingsTable.jsx`
- Create: `frontend/src/components/MisconfigTable.jsx`
- Test: `frontend/src/components/FindingsTable.test.jsx`

**Interfaces:**
- `FindingsTable` props: `{ findings: Array<{cve_id, cvss_score, cvss_severity, description, host}> }`
- `MisconfigTable` props: `{ misconfigs: Array<{host, port, title, description, severity}> }`

- [ ] **Step 1: Write failing test**

```jsx
// frontend/src/components/FindingsTable.test.jsx
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import FindingsTable from './FindingsTable'

const FINDINGS = [
  { cve_id: 'CVE-2021-41773', cvss_score: 9.8, cvss_severity: 'CRITICAL', description: 'Path traversal in Apache', host: '192.168.1.1' },
  { cve_id: 'CVE-2021-44228', cvss_score: 10.0, cvss_severity: 'CRITICAL', description: 'Log4Shell RCE', host: '192.168.1.2' },
  { cve_id: 'CVE-2020-1938', cvss_score: 9.8, cvss_severity: 'CRITICAL', description: 'Ghostcat AJP', host: '192.168.1.1' },
]

describe('FindingsTable', () => {
  it('renders all findings', () => {
    render(<FindingsTable findings={FINDINGS} />)
    expect(screen.getByText('CVE-2021-41773')).toBeInTheDocument()
    expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument()
  })

  it('shows empty state when no findings', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.getByText(/No CVE findings/)).toBeInTheDocument()
  })

  it('renders severity badges', () => {
    render(<FindingsTable findings={FINDINGS} />)
    const badges = screen.getAllByText('CRITICAL')
    expect(badges.length).toBeGreaterThanOrEqual(1)
  })

  it('renders row numbers', () => {
    render(<FindingsTable findings={FINDINGS} />)
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run -- FindingsTable
```

Expected: `Cannot find module './FindingsTable'`.

- [ ] **Step 3: Create FindingsTable.jsx**

```jsx
// frontend/src/components/FindingsTable.jsx
import React, { useState } from 'react'
import { ChevronUp, ChevronDown } from 'lucide-react'
import { sevClasses } from '../lib/severity'

const COLS = [
  { key: 'cvss_severity', label: 'Severity' },
  { key: 'cve_id', label: 'CVE ID' },
  { key: 'cvss_score', label: 'CVSS' },
  { key: 'host', label: 'Host' },
]

function Th({ col, sortCol, sortDir, onSort }) {
  const active = sortCol === col.key
  return (
    <th className="px-3 py-2 text-left">
      <button
        onClick={() => onSort(col.key)}
        className="flex items-center gap-1 hover:text-white text-xs font-semibold uppercase tracking-wide"
      >
        {col.label}
        {active && (sortDir === 'desc' ? <ChevronDown size={10} /> : <ChevronUp size={10} />)}
      </button>
    </th>
  )
}

export default function FindingsTable({ findings }) {
  const [sortCol, setSortCol] = useState('cvss_score')
  const [sortDir, setSortDir] = useState('desc')

  const handleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortCol(col); setSortDir('desc') }
  }

  if (!findings.length) {
    return <p className="text-slate-500 text-sm py-4">No CVE findings for this scan.</p>
  }

  const sorted = [...findings].sort((a, b) => {
    const av = a[sortCol] ?? '', bv = b[sortCol] ?? ''
    const cmp = av < bv ? -1 : av > bv ? 1 : 0
    return sortDir === 'desc' ? -cmp : cmp
  })

  return (
    <div className="overflow-x-auto rounded border border-slate-200">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-[#0f172a] text-slate-300">
            <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide w-8">#</th>
            {COLS.map(col => (
              <Th key={col.key} col={col} sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
            ))}
            <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide">Description</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f, i) => (
            <tr key={i} className={i % 2 === 0 ? 'bg-white' : 'bg-slate-50'}>
              <td className="px-3 py-2 text-slate-400 text-xs text-center">{i + 1}</td>
              <td className="px-3 py-2">
                <span className={sevClasses(f.cvss_severity)}>{f.cvss_severity || '?'}</span>
              </td>
              <td className="px-3 py-2 font-mono text-xs text-blue-700 whitespace-nowrap">{f.cve_id}</td>
              <td className="px-3 py-2 text-xs text-center font-mono">{f.cvss_score ?? 'N/A'}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{f.host}</td>
              <td className="px-3 py-2 text-xs text-slate-600 max-w-xs truncate">
                {(f.description || '').slice(0, 110)}{f.description?.length > 110 ? '…' : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
```

- [ ] **Step 4: Create MisconfigTable.jsx**

```jsx
// frontend/src/components/MisconfigTable.jsx
import React from 'react'
import { sevClasses } from '../lib/severity'

export default function MisconfigTable({ misconfigs }) {
  if (!misconfigs?.length) return null

  return (
    <div className="mt-6">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 border-b border-slate-200 pb-2">
        HTTP Misconfigurations ({misconfigs.length})
      </h3>
      <div className="overflow-x-auto rounded border border-slate-200">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-[#0f172a] text-slate-300 text-xs font-semibold uppercase tracking-wide">
              <th className="px-3 py-2 text-left">Host:Port</th>
              <th className="px-3 py-2 text-left">Finding</th>
              <th className="px-3 py-2 text-left">Detail</th>
              <th className="px-3 py-2 text-left">Severity</th>
            </tr>
          </thead>
          <tbody>
            {misconfigs.map((m, i) => (
              <tr key={i} className={i % 2 === 0 ? 'bg-white' : 'bg-slate-50'}>
                <td className="px-3 py-2 font-mono text-xs text-slate-600 whitespace-nowrap">
                  {m.host}:{m.port}
                </td>
                <td className="px-3 py-2 text-xs font-medium text-slate-700">{m.title}</td>
                <td className="px-3 py-2 text-xs text-slate-500 max-w-xs truncate">
                  {(m.description || '').slice(0, 90)}{(m.description || '').length > 90 ? '…' : ''}
                </td>
                <td className="px-3 py-2">
                  <span className={sevClasses(m.severity)}>{m.severity}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
```

- [ ] **Step 5: Run all tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: All tests PASS (14 + 4 FindingsTable = 18 total).

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/FindingsTable.jsx frontend/src/components/MisconfigTable.jsx \
        frontend/src/components/FindingsTable.test.jsx
git commit -m "feat(frontend): FindingsTable and MisconfigTable with sort and tests"
```

---

## Task 11: Frontend AssessmentPanel.jsx, ReportPanel.jsx, and ScanLog.jsx

The three supporting panels for the results view.

**Files:**
- Create: `frontend/src/components/AssessmentPanel.jsx`
- Create: `frontend/src/components/ReportPanel.jsx`
- Create: `frontend/src/components/ScanLog.jsx`

**Interfaces:**
- `AssessmentPanel` props: `{ result: {scan_id, score, grade, target, findings, misconfigs} }`
- `ReportPanel` props: `{ scanId: number }`
- `ScanLog` props: `{ lines: Array<{phase, text}> }`

- [ ] **Step 1: Create AssessmentPanel.jsx**

```jsx
// frontend/src/components/AssessmentPanel.jsx
import React, { useState } from 'react'
import { Sparkles, Loader2 } from 'lucide-react'
import { gradeColor } from '../lib/severity'
import { mdToHtml } from '../lib/mdToHtml'

export default function AssessmentPanel({ result }) {
  const [narration, setNarration] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const generate = async () => {
    setLoading(true)
    setErr('')
    try {
      const data = await fetch(`/api/narrate/${result.scan_id}`).then(r => r.json())
      setNarration(data.response || '')
    } catch {
      setErr('Failed to connect to AI. Check your API key in Settings.')
    } finally {
      setLoading(false)
    }
  }

  const grade = (result.grade || '').replace('Grade ', '') || '?'
  const gc = gradeColor(grade)
  const cveCount = result.findings?.length ?? 0
  const miscCount = result.misconfigs?.length ?? 0

  return (
    <div className="p-5">
      <div className="flex items-center gap-5 p-4 bg-slate-50 border border-slate-200 rounded-lg mb-5">
        <div className="text-6xl font-black leading-none font-mono" style={{ color: gc }}>
          {grade}
        </div>
        <div className="w-px bg-slate-200 self-stretch" />
        <div>
          <div className="font-bold text-slate-800 text-lg">{result.score}/100 Risk Score</div>
          <div className="text-slate-500 text-sm font-mono mt-0.5">{result.target}</div>
          <div className="text-slate-400 text-xs mt-1">
            {cveCount} CVE(s) &nbsp;·&nbsp; {miscCount} misconfiguration(s)
          </div>
        </div>
      </div>

      {!narration && !loading && (
        <button
          onClick={generate}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-sm font-medium"
        >
          <Sparkles size={14} />
          Generate AI Assessment
        </button>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-slate-500 text-sm">
          <Loader2 size={14} className="animate-spin" />
          AIVAS is analyzing…
        </div>
      )}

      {err && <p className="text-red-600 text-sm mt-2">{err}</p>}

      {narration && (
        <div
          className="text-slate-700 text-sm leading-relaxed mt-2 space-y-2"
          dangerouslySetInnerHTML={{ __html: mdToHtml(narration) }}
        />
      )}
    </div>
  )
}
```

- [ ] **Step 2: Create ReportPanel.jsx**

```jsx
// frontend/src/components/ReportPanel.jsx
import React from 'react'
import { FileText, Download } from 'lucide-react'

export default function ReportPanel({ scanId }) {
  return (
    <div className="p-5">
      <div className="flex gap-3 mb-5">
        <a
          href={`/api/report/${scanId}`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-md hover:bg-slate-50 text-sm text-slate-700 transition-colors"
        >
          <FileText size={14} />
          View HTML Report
        </a>
        <a
          href={`/api/report/${scanId}/pdf`}
          download={`aivas-report-${scanId}.pdf`}
          className="flex items-center gap-2 px-4 py-2 bg-[#0f172a] hover:bg-slate-700 text-white rounded-md text-sm font-medium transition-colors"
        >
          <Download size={14} />
          Download PDF
        </a>
      </div>
      <p className="text-xs text-slate-400 leading-relaxed max-w-prose">
        Report is suitable for submission to IT managers and compliance officers.
        Generated automatically from scan data — validate with a qualified security
        professional before inclusion in official documentation or compliance submissions.
      </p>
    </div>
  )
}
```

- [ ] **Step 3: Create ScanLog.jsx**

```jsx
// frontend/src/components/ScanLog.jsx
import React, { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

export default function ScanLog({ lines }) {
  const [open, setOpen] = useState(false)

  if (!lines?.length) return null

  return (
    <div className="border-t border-slate-100">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-5 py-2.5 text-xs text-slate-400 hover:text-slate-600 w-full text-left transition-colors"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        View scan log ({lines.length} events)
      </button>
      {open && (
        <div className="bg-slate-50 border-t border-slate-100 px-5 py-3 max-h-56 overflow-y-auto">
          {lines.map((ev, i) =>
            ev.phase === 'phase_header' ? (
              <div key={i} className="text-xs font-medium text-slate-400 uppercase tracking-widest mt-2 mb-0.5 border-b border-slate-200 pb-0.5 first:mt-0">
                {ev.text}
              </div>
            ) : (
              <div key={i} className="font-mono text-xs text-slate-500 leading-5">{ev.text}</div>
            )
          )}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 4: Run all tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: 18 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/AssessmentPanel.jsx frontend/src/components/ReportPanel.jsx \
        frontend/src/components/ScanLog.jsx
git commit -m "feat(frontend): AssessmentPanel, ReportPanel, ScanLog components"
```

---

## Task 12: Frontend ResultsTabs.jsx

Tabbed container combining Findings, Assessment, and Report tabs plus the scan log.

**Files:**
- Create: `frontend/src/components/ResultsTabs.jsx`

**Interfaces:**
- Props: `{ result: doneEvent, progressLines: Array }`
- `result` shape: `{ findings, misconfigs, scan_id, score, grade, target }`
- Tab 'findings' shows `FindingsTable` + `MisconfigTable`; tab 'assessment' shows `AssessmentPanel`; tab 'report' shows `ReportPanel`
- `ScanLog` is always rendered below the tab content with the full `progressLines`

- [ ] **Step 1: Create ResultsTabs.jsx**

```jsx
// frontend/src/components/ResultsTabs.jsx
import React, { useState } from 'react'
import FindingsTable from './FindingsTable'
import MisconfigTable from './MisconfigTable'
import AssessmentPanel from './AssessmentPanel'
import ReportPanel from './ReportPanel'
import ScanLog from './ScanLog'

const TABS = [
  { key: 'findings', label: 'Findings' },
  { key: 'assessment', label: 'Assessment' },
  { key: 'report', label: 'Report' },
]

export default function ResultsTabs({ result, progressLines }) {
  const [tab, setTab] = useState('findings')
  const { findings = [], misconfigs = [], scan_id } = result

  return (
    <div>
      <div className="flex border-b border-slate-200 px-1 bg-white">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.key
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
            }`}
          >
            {t.label}
            {t.key === 'findings' && findings.length > 0 && (
              <span className="ml-1.5 text-xs bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded-full">
                {findings.length}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="bg-white">
        {tab === 'findings' && (
          <div className="p-4">
            {findings.length === 0 && misconfigs.length === 0 ? (
              <p className="text-slate-500 text-sm py-6 text-center">No findings for this scan.</p>
            ) : (
              <>
                {findings.length > 0 && (
                  <>
                    <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 border-b border-slate-200 pb-2">
                      CVE Findings ({findings.length})
                    </h3>
                    <FindingsTable findings={findings} />
                  </>
                )}
                <MisconfigTable misconfigs={misconfigs} />
              </>
            )}
          </div>
        )}
        {tab === 'assessment' && <AssessmentPanel result={result} />}
        {tab === 'report' && <ReportPanel scanId={scan_id} />}
      </div>

      <ScanLog lines={progressLines} />
    </div>
  )
}
```

- [ ] **Step 2: Run all tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: 18 tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/ResultsTabs.jsx
git commit -m "feat(frontend): ResultsTabs — Findings/Assessment/Report tabs + scan log"
```

---

## Task 13: Frontend App.jsx + Build Verification

Wire all components into the main layout shell and verify the full build compiles without errors.

**Files:**
- Modify: `frontend/src/App.jsx` (replace placeholder with full implementation)

**Interfaces:**
- Consumes: all components, `useWebSocket`, `useHistory`
- State: `activeScanId` (which sidebar entry is highlighted), `historyScan` (scan loaded from history)
- When a live scan finishes (`isDone`), it takes priority over `historyScan`
- When user clicks a history entry, live scan state is reset and history findings are loaded

- [ ] **Step 1: Replace App.jsx**

```jsx
// frontend/src/App.jsx
import React, { useState, useCallback } from 'react'
import { Shield } from 'lucide-react'
import Sidebar from './components/Sidebar'
import ScanBar from './components/ScanBar'
import ProgressFeed from './components/ProgressFeed'
import ResultsTabs from './components/ResultsTabs'
import { useWebSocket } from './hooks/useWebSocket'
import { useHistory } from './hooks/useHistory'

function EmptyState() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-center p-10 select-none">
      <Shield size={52} className="text-slate-200 mb-4" />
      <h2 className="text-2xl font-bold text-slate-300 mb-2 tracking-tight">AIVAS</h2>
      <p className="text-slate-400 text-sm">AI-Assisted Vulnerability Assessment System</p>
      <p className="text-slate-400 text-sm mt-5">Enter a target in the bar above to begin scanning</p>
      <p className="text-slate-300 text-xs mt-1.5 font-mono">
        e.g.&nbsp; 192.168.1.1 &nbsp;or&nbsp; 10.0.0.0/24
      </p>
    </div>
  )
}

export default function App() {
  const { scans, refresh: refreshHistory, deleteScan } = useHistory()
  const [activeScanId, setActiveScanId] = useState(null)
  const [historyScan, setHistoryScan] = useState(null)

  const { status, progressLines, result, errorMsg, startScan, reset, isScanning, isDone } =
    useWebSocket({ onScanComplete: refreshHistory })

  const handleScan = useCallback((target, level) => {
    setHistoryScan(null)
    setActiveScanId(null)
    startScan(target, level)
  }, [startScan])

  const handleSelectScan = useCallback(async (scan) => {
    reset()
    setActiveScanId(scan.id)
    try {
      const findings = await fetch(`/api/scan/${scan.id}`).then(r => r.json())
      setHistoryScan({
        scan_id: scan.id,
        target: scan.target,
        score: scan.risk_score,
        grade: scan.grade,
        findings: Array.isArray(findings) ? findings : [],
        misconfigs: [],
      })
    } catch {
      setHistoryScan(null)
    }
  }, [reset])

  const handleDeleteScan = useCallback(async (id) => {
    await deleteScan(id)
    if (activeScanId === id) {
      setActiveScanId(null)
      setHistoryScan(null)
    }
  }, [deleteScan, activeScanId])

  const displayResult = isDone ? result : historyScan
  const showFeed = isScanning || status === 'error'

  return (
    <div className="flex min-h-screen bg-[#f8fafc]">
      <Sidebar
        scans={scans}
        onNewScan={() => { reset(); setHistoryScan(null); setActiveScanId(null) }}
        onSelectScan={handleSelectScan}
        onDeleteScan={handleDeleteScan}
        onSettings={() => {}}
        activeScanId={activeScanId}
      />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <ScanBar onScan={handleScan} isScanning={isScanning} />
        <div className="flex-1 overflow-y-auto">
          {showFeed && (
            <div className="mx-4 mt-4 bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
              <ProgressFeed lines={progressLines} />
              {status === 'error' && (
                <div className="px-4 pb-4 text-red-600 text-sm font-mono">{errorMsg}</div>
              )}
            </div>
          )}
          {displayResult ? (
            <div className={`mx-4 mt-4 bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden ${showFeed ? '' : ''}`}>
              <ResultsTabs
                result={displayResult}
                progressLines={isDone ? progressLines : []}
              />
            </div>
          ) : !showFeed ? (
            <EmptyState />
          ) : null}
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Run all tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm run test:run
```

Expected: All 18 tests PASS.

- [ ] **Step 3: Build the React app**

```bash
cd /home/cyberpunk/aivas/frontend
npm run build
```

Expected: Vite completes successfully. Output directory `frontend/dist/` is created containing `index.html` and `assets/`.

Verify:
```bash
ls /home/cyberpunk/aivas/frontend/dist/
```

Expected: `index.html  assets/`

- [ ] **Step 4: Add dist to .gitignore**

Add to `/home/cyberpunk/aivas/.gitignore` (create if it doesn't exist):

```
frontend/dist/
frontend/node_modules/
```

- [ ] **Step 5: Run full backend test suite to confirm no regressions**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/ -v --ignore=tests/test_ssh_probe.py -x -q 2>&1 | tail -20
```

Expected: All tests PASS (the ssh probe test may fail if paramiko connection is unavailable — it's excluded).

- [ ] **Step 6: Final commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/App.jsx .gitignore
git commit -m "feat(frontend): App.jsx wires all components; full React UI complete"
```

---

## Development Workflow Reference

**Run backend + frontend in parallel during development:**

Terminal 1 (backend):
```bash
cd /home/cyberpunk/aivas
aivas serve
```

Terminal 2 (frontend dev server with HMR and API proxy):
```bash
cd /home/cyberpunk/aivas/frontend
npm run dev
```

Open `http://localhost:5173` — the Vite dev server proxies `/api` and `/ws` to FastAPI on port 8000.

**Production serving (after `npm run build`):**

```bash
cd /home/cyberpunk/aivas
aivas serve
```

Open `http://localhost:8000` — FastAPI serves `frontend/dist/` directly.
