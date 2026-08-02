# AI Core Fixes — Spec 1

**Goal:** Fix every bug that makes the AI wrong, amnesiac, or fragile. No new UI. Pure correctness and reliability.

**Architecture:** Six independent fixes across three layers — TUI conversation memory, web harness reliability, tool correctness, and two small frontend patches. Each fix is self-contained; they can be reviewed and reverted independently.

**Tech Stack:** Python (FastAPI backend, Textual TUI), React frontend, Groq API (llama-3.3-70b-versatile), SQLite

---

## Global Constraints

- No file exceeds 200 lines of code
- One module = one responsibility
- All fixes must not break existing tests
- No new dependencies
- The `discover_hosts` tool must degrade gracefully when nmap lacks raw socket capability (return IPs + hostnames only, note MAC requires root)

---

## Files Changed

| File | Change |
|---|---|
| `aivas/tui/ai.py` | Store and pass conversation history per session |
| `aivas/tui/agent.py` | Add `discover_hosts` tool; raise findings truncation limits |
| `aivas/tui/agent_prompts.py` | Add `discover_hosts` schema; mandatory `get_findings` rule; routing rule |
| `aivas/server/chat_stream.py` | Upgrade model; add retry; inject scan context; tool errors recoverable |
| `aivas/history.py` | Add per-severity counts to `list_scans()` return |
| `frontend/src/App.jsx` | Fix welcome-back message (use real counts from history API) |
| `frontend/src/hooks/useScan.js` | Fix `ws.onerror` to call `onDoneRef` so hung UI is replaced |

---

## Fix 1: TUI Conversation Memory

**File:** `aivas/tui/ai.py`

**Bug:** `dispatch()` calls `run_agent(..., history=None)` and discards `turns_to_persist` with `_`. Every message is a fresh conversation.

**Fix:** Track `app._chat_history: list[dict]` on the app instance. Pass it into `run_agent`. After each call, extend it with the returned turns and cap at 12 entries (6 exchange pairs) to prevent unbounded growth.

```python
# In AIVASApp.__init__, add:
self._chat_history: list[dict] = []

# In dispatch(), replace line 83:
history = getattr(app, '_chat_history', [])
response, scan_intent, turns = await run_agent(
    app, text, api_key, context=context, history=history
)
app._chat_history = (history + turns)[-12:]
```

Clear `_chat_history` when the user runs `/clear` (action_clear_output) so memory resets with the screen.

---

## Fix 2: Web Harness Reliability

**File:** `aivas/server/chat_stream.py`

### 2a — Model upgrade

Replace `llama-3.1-8b-instant` with `llama-3.3-70b-versatile` in the Phase A Groq call (line 87). Same model the TUI already uses. More reliable at tool calling; no other change needed.

### 2b — Retry on tool_use_failed

Wrap the Phase A call in a try/except. On exceptions containing `"400"` or `"tool"` in the message (the Groq `tool_use_failed` pattern), retry once with `tools=None`. If the retry also fails, yield a friendly error message — never a raw exception string.

```python
try:
    resp = await asyncio.to_thread(lambda: groq.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        tools=_TOOLS,
        tool_choice="auto",
        max_tokens=600,
    ))
except Exception as exc:
    s = str(exc)
    if "400" in s or "tool" in s.lower():
        # Retry without tools
        try:
            resp = await asyncio.to_thread(lambda: groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=600,
            ))
            # Fall through to streaming response
        except Exception as retry_exc:
            yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
            return
    else:
        yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
        return
```

### 2c — Tool errors as recoverable results

In `_exec_tool_local`, wrap the call in try/except. On exception, return the error as a JSON tool result so the model can read it and adapt — not crash:

```python
try:
    result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)
except Exception as exc:
    result = json.dumps({"error": f"Tool execution failed: {exc}"})
    scan_intent = None
```

### 2d — Inject scan history context

After loading `session_history`, query the DB for the 3 most recent scans and prepend a context block to the system prompt — mirroring what the TUI's `build_context()` does:

```python
from aivas.history import list_scans as _list_scans

def _build_web_context(conn) -> str:
    scans = _list_scans(conn, limit=3)
    if not scans:
        return ""
    lines = ["Recent scans:"]
    for s in scans:
        lines.append(
            f"  · scan #{s['id']}: {s['target']} — Grade {s.get('grade','?')}, "
            f"{s.get('finding_count', 0)} findings"
        )
    return "\n".join(lines)

# In stream_agent_response, build the system prompt:
ctx = _build_web_context(conn)
system = "\n\n".join(filter(None, [_SYSTEM, ctx]))
messages = [{"role": "system", "content": system}]
```

---

## Fix 3: discover_hosts Tool

**Files:** `aivas/tui/agent.py`, `aivas/tui/agent_prompts.py`

### Tool implementation (`agent.py`)

New branch in `_exec_tool`:

```python
if name == "discover_hosts":
    import shutil, asyncio
    target = _as_str(args.get("target"))
    if not target:
        return json.dumps({"error": "target (CIDR or IP range) is required."}), None

    nmap_bin = shutil.which("nmap") or "nmap"
    # -sn = ping sweep only (no port scan)
    # --script=nbstat for NetBIOS names where available
    cmd = [nmap_bin, "-sn", "-oX", "-", target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    except Exception as exc:
        return json.dumps({"error": f"Host discovery failed: {exc}"}), None

    import xml.etree.ElementTree as ET
    devices = []
    try:
        root = ET.fromstring(stdout.decode())
        for host in root.findall("host"):
            if host.find("status") is None or host.find("status").get("state") != "up":
                continue
            dev: dict = {}
            for addr in host.findall("address"):
                atype = addr.get("addrtype", "")
                if atype == "ipv4":
                    dev["ip"] = addr.get("addr")
                elif atype == "mac":
                    dev["mac"] = addr.get("addr")
                    vendor = addr.get("vendor")
                    if vendor:
                        dev["vendor"] = vendor
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname[@type='PTR']") or hostnames.find("hostname")
                if hn is not None:
                    dev["hostname"] = hn.get("name")
            if dev.get("ip"):
                devices.append(dev)
    except Exception as exc:
        return json.dumps({"error": f"Could not parse discovery output: {exc}"}), None

    note = ""
    if devices and not any(d.get("mac") for d in devices):
        note = "MAC addresses not available — nmap may need cap_net_raw capability (see /doctor)."

    return json.dumps({"devices": devices, "count": len(devices), "note": note}), None
```

Because `_exec_tool` is synchronous but `discover_hosts` needs `await`, the implementation wraps it with `asyncio.get_event_loop().run_until_complete()` in the TUI path (which is already in an async context via `run_agent`). Alternatively, refactor `_exec_tool` to be async — see note in implementation plan.

### Tool schema (`agent_prompts.py`)

```python
{"type": "function", "function": {
    "name": "discover_hosts",
    "description": (
        "List all devices on a network without scanning for vulnerabilities. "
        "Use this when the user asks how many devices are on the network, who is connected, "
        "what devices exist, or any question about network topology — without asking to scan "
        "for vulnerabilities or security issues. Returns IP, hostname, MAC, and vendor."
    ),
    "parameters": {"type": "object", "required": ["target"], "properties": {
        "target": {"type": "string", "description": "CIDR range e.g. 10.88.91.0/24"},
    }},
}},
```

### System prompt additions (`agent_prompts.py`)

Add to the Rules section:

```
- ROUTING RULE: Use discover_hosts when the user asks about devices, who is connected,
  how many devices are on the network, or network topology. Only use scan_host when the
  user explicitly asks to scan for vulnerabilities, CVEs, security issues, or weaknesses.
- HONESTY RULE: Before giving any risk summary, remediation advice, or CVE analysis for
  a specific scan, you MUST call get_findings(scan_id) first. Never describe scan results
  from memory — only from tool output returned in this conversation.
```

---

## Fix 4: Findings Truncation

**File:** `aivas/tui/agent.py`

Raise the caps so the AI sees complete data:

```python
# get_last_scan: line 68
findings = get_scan_findings(conn, scans[0]["id"])
return json.dumps({"scan": scans[0], "findings": findings[:25]}), None  # was 10

# get_findings: line 76
findings = get_scan_findings(conn, scan_id)
return json.dumps(findings[:50]), None  # was 15
```

---

## Fix 5: History API — Add Severity Counts

**File:** `aivas/history.py`

`list_scans()` currently returns no per-severity breakdown. Add a subquery for CRITICAL count so the welcome-back message can show meaningful data:

```python
SELECT s.id, s.target, s.started_at, s.finding_count, s.risk_score, s.grade,
       COALESCE((
         SELECT COUNT(*) FROM findings f JOIN cves c ON c.cve_id = f.cve_id
         WHERE f.scan_id = s.id AND c.kev = 1
       ), 0) AS kev_count,
       COALESCE((
         SELECT COUNT(*) FROM findings f JOIN cves c ON c.cve_id = f.cve_id
         WHERE f.scan_id = s.id AND c.cvss_severity = 'CRITICAL'
       ), 0) AS critical_count
  FROM scans s
 ORDER BY s.id DESC
 LIMIT ?
```

---

## Fix 6: Welcome-Back Message

**File:** `frontend/src/App.jsx`

Replace the broken `scan.counts?.CRITICAL ?? 0` read with fields that actually exist in the history API response after Fix 5:

```js
const critical = scan.critical_count ?? 0
const kev = scan.kev_count ?? 0
const days = daysAgo(scan.started_at)
const grade = (scan.grade || '').replace('Grade ', '')
text =
  `Welcome back. Your last scan of ${scan.target} was ${days} day${days !== 1 ? 's' : ''} ago` +
  ` — Grade ${grade}, ${scan.finding_count ?? 0} findings` +
  (critical > 0 ? `, ${critical} critical` : '') +
  (kev > 0 ? `, ${kev} actively exploited` : '') +
  `. Want me to rescan, or would you like a summary?`
```

---

## Fix 7: useScan.js onerror Hangs UI

**File:** `frontend/src/hooks/useScan.js`

Current `ws.onerror` only sets `isScanning(false)` — the scan-progress card stays frozen. Fix: call `onDoneRef` so the card is replaced with an error message:

```js
ws.onerror = () => {
  ws.onerror = null
  setIsScanning(false)
  onDoneRef.current({
    type: 'error',
    text: 'Connection to scan service lost. Check that the server is running and try again.',
    log: logRef.current,
  })
}
```

---

## Out of Scope

- UDP scanning, OS detection, level 3 distinction — deferred to final scan capabilities spec
- SSH probe — deferred pending hardware testing
- Live tool visibility (ToolCall/ToolResult events to frontend) — Spec 2
- Remediation script generation — Spec 3
