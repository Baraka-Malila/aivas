# AIVAS AI Honesty + Conversational Backend — Phase 1 Design Spec

> **Status:** Drafted 2026-06-30. Pending user review.
> **Scope:** Backend only. Frontend redesign is Phase 2, depending on this spec landing first.

---

## 1. Why

Today AIVAS markets itself as "AI-Assisted Vulnerability Assessment System" but the AI claim is largely theatre:

- **Chat has no memory.** `chat_api.handle_chat` calls `run_agent(text, ...)` which builds `messages = [system, user]` from scratch every request. Follow-up questions are impossible.
- **Web scans skip the AI narrator entirely.** `scan_worker.run_scan` calls `save_scan` directly without ever invoking `aivas.narrator.narrate()`. Every web-initiated finding lands in the DB with empty `narration_en`, `narration_sw`, `fix_en`, `fix_sw`. The CLI has rich AI narration; the web has none.
- **Remediation is a keyword switch.** `report_helpers.cve_fix()` is 9 hardcoded branches matching CVE description against fixed wordlists. Every "RCE" CVE gets the same sentence. The HTML and PDF reports rely on this.
- **KEV is tracked and ignored.** `database/kev.py` marks CVEs that CISA confirms are actively exploited. `scorer.py`, `report_helpers.py`, `report_gen.py` never read the field. The grade for a host with a Known Exploited Vulnerability is identical to a host without one.
- **Language detection is a 23-word Swahili keyword set.** Code-switching, French, Spanish, or Kinyarwanda input all collapse to English.
- **LLM-supplied tool arguments are passed to `int()` unchecked.** A hallucinated `level="full"` or `scan_id="latest"` crashes the agent loop.
- **HTTP prober treats unreachable hosts as clean.** Broad `except Exception: pass` returns `[]` for both network failure and a host that genuinely has no findings. False negative dressed as a clean bill of health.

Phase 1 fixes the AI honesty problem at the backend so that Phase 2 (a chat-first frontend) is something we can actually build without lying to the user.

---

## 2. Scope

### In scope

| Group | Item |
|---|---|
| A. Conversation | `chat_sessions` + `chat_messages` SQLite tables; load/save/truncate helpers |
| A. Conversation | Multi-turn history passed to Groq each turn |
| A. Conversation | `WS /ws/chat/{session_id}` for token streaming + interrupt |
| A. Conversation | Session REST: list / read / delete |
| A. Conversation | Drop `_detect_lang` 23-word heuristic; instruct LLM to mirror user's language |
| B. AI honesty | Wire `narrate()` into `scan_worker` so web scans get EN+SW narration parity with CLI |
| B. AI honesty | Replace `cve_fix()` switch with LLM-cached `cve_advice` table; warm at scan end |
| B. AI honesty | KEV findings: 1.5× CVSS penalty multiplier in scorer; hard grade cap at C (≤75/100); UI flag in reports |
| C. Demo safety | Validate every LLM-supplied tool argument before casting; return JSON error rather than raising |
| C. Demo safety | Prober returns `{"status": "unreachable"\|"clean"\|"findings"}` instead of swallowing failures |

### Out of scope (Phase 2 or later)

- Frontend redesign (chat-first web UI — separate spec, depends on this one)
- Correlator backport-aware version matching (research-grade; document the limitation in reports instead)
- RAG / vector store / sentence-transformer embeddings (no unstructured corpus to retrieve from yet)
- Schema versioning, `_pending` TTL, NSE script validation, executive-summary contextualisation — minor, deferred
- Voice STT/TTS, mobile UI, authentication
- Groq → Ollama resilience fallback (consider after first production use shows rate-limit pain)

---

## 3. Tech Stack

No new runtime dependencies. Uses existing `groq` SDK, `fastapi`, `sqlite3`, `asyncio`. WebSockets via existing FastAPI support.

---

## 4. Data Model

Three new SQLite tables. All inside the existing `DB_PATH` database; created by `database/schema.py:create_schema` alongside scans/findings/cves.

### 4.1 `chat_sessions`

```sql
CREATE TABLE IF NOT EXISTS chat_sessions (
    id          TEXT PRIMARY KEY,                       -- UUID v4
    title       TEXT,                                   -- LLM-suggested or first user message truncated
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

Sessions are never auto-deleted. User explicitly deletes via API. The `updated_at` is bumped on each new message; useful for ordering by recency.

### 4.2 `chat_messages`

```sql
CREATE TABLE IF NOT EXISTS chat_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK(role IN ('user','assistant','tool')),
    content      TEXT,                                  -- assistant text or user text; NULL for pure-tool-call assistant turns
    tool_calls   TEXT,                                  -- JSON: assistant turn's tool_calls array if any
    tool_call_id TEXT,                                  -- only when role='tool' — which assistant tool_call this answers
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session_time
    ON chat_messages(session_id, created_at);
```

`role='system'` is **not** stored — the system prompt is recomputed each turn from current scan context.

### 4.3 `cve_advice`

```sql
CREATE TABLE IF NOT EXISTS cve_advice (
    cve_id      TEXT PRIMARY KEY,
    advice_en   TEXT NOT NULL,
    advice_sw   TEXT NOT NULL,
    model       TEXT NOT NULL,                          -- e.g. 'llama-3.3-70b-versatile'
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

Cache of LLM-generated per-CVE remediation. Idempotent per `cve_id`. Cache hit returns instantly; miss triggers LLM call (warmed at scan end, see §6).

---

## 5. Conversation Memory

### 5.1 New module `aivas/server/chat_memory.py`

Public API:

```python
def create_session(conn, title: str | None = None) -> str: ...
    # Insert row, return new UUID

def get_session(conn, session_id: str) -> dict | None: ...
    # Return {id, title, created_at, updated_at} or None

def list_sessions(conn, limit: int = 20) -> list[dict]: ...
    # Order by updated_at DESC

def delete_session(conn, session_id: str) -> bool: ...
    # ON DELETE CASCADE handles messages

def load_history(conn, session_id: str, max_turns: int = 6) -> list[dict]: ...
    # Return last `max_turns` pairs (i.e. up to 12 rows) in Groq message format:
    # [{"role": "user", "content": "..."},
    #  {"role": "assistant", "content": "...", "tool_calls": [...]} | {"role":"assistant","content":"..."},
    #  {"role": "tool", "tool_call_id": "...", "content": "..."}, ...]
    # Truncation rule: drop oldest user-assistant pairs first; never split a pair, never strand a tool result.

def save_user(conn, session_id: str, text: str) -> None: ...
def save_assistant(conn, session_id: str, text: str, tool_calls: list | None = None) -> None: ...
def save_tool_result(conn, session_id: str, tool_call_id: str, result: str) -> None: ...
def update_title_if_unset(conn, session_id: str, first_user_text: str) -> None: ...
    # Set title = first 60 chars of first user message if title is NULL.

def touch_session(conn, session_id: str) -> None: ...
    # Bump updated_at
```

`max_turns=6` is the default trim depth. A turn = one user message + the assistant response (including any tool-call/tool-result steps that produced it). Older turns are dropped wholesale, never partially.

### 5.2 Rewrite `aivas/server/chat_api.py`

```python
async def handle_chat(
    conn: sqlite3.Connection,
    session_id: str,
    text: str,
    current_scan_id: int | None = None,
) -> tuple[str, tuple[str, int] | None]:
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return ("No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY", None)

    # 1. Load prior conversation
    history = load_history(conn, session_id, max_turns=6)

    # 2. Build context block (scan state, NOT prior chat — chat lives in `history`)
    context = _build_context(conn, scan_id=current_scan_id)

    # 3. Save user message before LLM call (so it persists even if LLM errors)
    save_user(conn, session_id, text)
    update_title_if_unset(conn, session_id, text)

    # 4. Call agent with full message array
    from aivas.tui.agent import run_agent
    holder = types.SimpleNamespace(conn=conn)
    try:
        response, scan_intent, assistant_turns = await run_agent(
            holder, text, api_key,
            context=context,
            history=history,
        )
    except Exception as exc:
        # ...existing error mapping...
        return (f"AI error: {exc}", None)

    # 5. Persist assistant turn(s) — there may be multiple if the agent looped through tools
    for turn in assistant_turns:
        if turn["role"] == "assistant":
            save_assistant(conn, session_id, turn["content"], turn.get("tool_calls"))
        elif turn["role"] == "tool":
            save_tool_result(conn, session_id, turn["tool_call_id"], turn["content"])

    touch_session(conn, session_id)
    return (response or "", scan_intent)
```

### 5.3 Rewrite `aivas/tui/agent.py:run_agent`

Signature change:

```python
async def run_agent(
    app, text: str, api_key: str,
    context: str = "",
    history: list[dict] | None = None,
) -> tuple[str, tuple | None, list[dict]]:
    """
    Returns (final_response_text, scan_intent | None, assistant_turns_to_persist).
    assistant_turns_to_persist is the new messages produced this call:
      [{"role":"assistant","content":"...","tool_calls":[...]?},
       {"role":"tool","tool_call_id":"...","content":"..."},
       ...]
    The caller persists these via chat_memory.
    """
```

Inside, replace the existing `orig_messages = [system, user]` with:

```python
system = _compose_system_prompt(context)        # see §10 for multilingual change
messages = [{"role": "system", "content": system}]
if history:
    messages.extend(history)
messages.append({"role": "user", "content": text})
```

The system prompt is fully rebuilt each turn — it carries fresh scan context. Conversation memory lives in `history`. This is the bongoSTEM pattern: composable system block + actual chat below.

Backward compatibility: the TUI calls `run_agent` without `history`. Tuple unpacking changes from 2-tuple to 3-tuple — update TUI call sites to ignore the third element.

### 5.4 Tool call execution

`_exec_tool` already returns `(result_json, scan_intent)`. The tool loop in `run_agent` collects each tool call + result as it goes:

```python
turns_to_persist: list[dict] = []
for _step in range(_MAX_STEPS):
    resp = await asyncio.to_thread(_call, messages, _TOOLS)
    msg = resp.choices[0].message
    if not msg.tool_calls:
        turns_to_persist.append({"role": "assistant", "content": msg.content or ""})
        return msg.content or "", scan_intent, turns_to_persist
    # Record assistant tool-call turn
    assistant_turn = {
        "role": "assistant",
        "content": msg.content or "",
        "tool_calls": [...],
    }
    turns_to_persist.append(assistant_turn)
    messages.append(assistant_turn)
    # Execute tools, record each tool result
    for tc in msg.tool_calls:
        args = _safe_args(tc.function.arguments)   # see §9
        result, si = _exec_tool(tc.function.name, args, app.conn)
        if si: scan_intent = si
        tool_turn = {"role":"tool", "tool_call_id":tc.id, "content":result}
        messages.append(tool_turn)
        turns_to_persist.append(tool_turn)
```

---

## 6. Web Scan Narration (parity with CLI)

### 6.1 Current state

`scan_worker.run_scan` ends with:

```python
scan_id = save_scan(conn, target, findings)
yield {"type":"done", "target":target, "scan_id":scan_id, ...}
```

`findings` is the raw correlator output with `narration_en`, `narration_sw`, `fix_en`, `fix_sw` all empty strings. `history.save_scan` writes them as empty.

### 6.2 Change

Between scoring and `save_scan`, run the narrator over all findings:

```python
yield _ev("phase_header", "AI NARRATION")
yield _ev("narrate", f"Generating bilingual narrations for {len(findings)} finding(s)…")
findings = await asyncio.to_thread(narrate_findings, findings, api_key)
scan_id = save_scan(conn, target, findings)
```

Where `narrate_findings(findings, api_key) -> list[dict]` is a small wrapper around the existing `aivas.narrator.narrate` that:

1. Iterates findings (capped at top 30 by CVSS score)
2. Generates `narration_en`, `narration_sw`, `fix_en`, `fix_sw` per finding using **the same logic the CLI uses**
3. Returns the list with fields populated

If `api_key` is missing or Groq is down, narration is skipped silently — findings still save with empty fields, and reports fall back to the existing `cve_fix` switch (which §7 also rewires). The scan does not fail because narration failed.

This adds 5-15s to a typical scan depending on CVE count. Acceptable for an async background job; the WebSocket already streams progress.

### 6.3 KEV warning flag in findings

While iterating, set `finding["kev"] = bool(<lookup result>)` so downstream reports/scorer can use it without re-querying.

---

## 7. Per-CVE LLM Remediation

### 7.1 New module `aivas/server/cve_advice.py`

```python
def get_advice(conn, cve_id: str) -> dict | None:
    """Return {advice_en, advice_sw, model, created_at} or None if not cached."""

def put_advice(conn, cve_id: str, advice_en: str, advice_sw: str, model: str) -> None:
    """Upsert into cve_advice."""

async def generate_advice(cve_id: str, cve_row: dict, api_key: str) -> tuple[str, str]:
    """Call Groq once. Returns (advice_en, advice_sw). Times out at 15s."""

async def warm_cache(conn, cve_ids: list[str], api_key: str, max_concurrent: int = 5) -> None:
    """For each cve_id not already in cve_advice, generate and cache. Bounded concurrency.
       Skip silently on errors — fall back to template when consumed."""
```

### 7.2 Prompt for `generate_advice`

```
You are a security engineer producing concise, ACTIONABLE remediation advice for a single CVE.

CVE: {cve_id}
CVSS: {cvss_score} ({cvss_severity})
Affected: {product} {version}
Description: {description}

Output two short paragraphs, separated by a blank line.

Paragraph 1 — ENGLISH:
3-5 sentences. Lead with the specific software/version to upgrade to. Name compensating controls (firewall rule, config setting, disabled feature) the admin can apply TODAY if upgrade is impossible. End with one sentence on detection (log location, IOC, network signature) if relevant.

Paragraph 2 — KISWAHILI:
Same content as paragraph 1, rendered in Kiswahili. Use clear, plain language a Tanzanian IT admin would understand. Keep CVE IDs, version numbers, and product names in their original Latin form.

Do not output headings, bullets, or markdown. Two paragraphs. That is the whole output.
```

### 7.3 Replace `cve_fix`

`report_helpers.cve_fix(f)` becomes:

```python
def cve_fix(f: dict, conn: sqlite3.Connection | None = None, lang: str = "en") -> str:
    cve_id = f.get("cve_id", "")
    # 1. Stored on finding (CLI narrate path)
    fix = (f.get(f"fix_{lang}") or "").strip()
    if fix:
        return fix
    # 2. Cached LLM advice
    if conn is not None:
        cached = get_advice(conn, cve_id)
        if cached:
            return cached[f"advice_{lang}"]
    # 3. Old keyword switch as last-resort template
    return _legacy_template_fix(f, lang)
```

`_legacy_template_fix` is the current `cve_fix` body, kept verbatim but renamed so it's obvious in code review that it's the fallback. Caller passes `conn` in so the cache can be consulted.

### 7.4 Warmup at scan end

In `scan_worker.run_scan`, immediately after narration:

```python
yield _ev("phase_header", "AI REMEDIATION")
cve_ids = [f["cve_id"] for f in findings if f.get("cve_id")]
yield _ev("advice", f"Generating remediation advice for {len(cve_ids)} CVE(s)…")
await warm_cache(conn, cve_ids, api_key, max_concurrent=5)
```

Bounded concurrency at 5 to respect Groq free-tier rate limits. If `api_key` missing or any individual call fails, warm_cache logs and continues; reports use templates for those CVEs.

---

## 8. KEV Integration

### 8.1 Scorer change (`aivas/scorer.py`)

Current penalty calculation (top 5 CVEs, sum CVSS) gets a KEV multiplier:

```python
KEV_MULT = 1.5

def _per_finding_penalty(f: dict) -> float:
    base = float(f.get("cvss_score") or 0.0)
    return base * (KEV_MULT if f.get("kev") else 1.0)
```

Use `_per_finding_penalty` wherever the current code multiplies by raw CVSS. Sort findings by this penalised value (not raw CVSS) when picking the top-5 contributors.

### 8.2 Hard grade cap

After computing `score`, `grade`:

```python
if any(f.get("kev") for f in findings):
    # Cap at C (≤75) — a known-exploited CVE on your network is never an A or B.
    if score > 75:
        score = 75
    if grade in ("A", "B"):
        grade = "C"
```

### 8.3 Report integration

In `aivas/templates/report.html.j2`, add a `KNOWN EXPLOITED` pill (red, with a small flame glyph) on KEV finding rows. Sort findings so KEV findings float to the top of their severity group.

In the executive summary (`executive_summary`), prepend a KEV warning sentence if any KEV finding exists:

```
"This host has {N} actively-exploited vulnerabilit{y/ies} listed in CISA's KEV catalog. These are confirmed in-the-wild attacks; remediation cannot wait."
```

### 8.4 Sidebar / history rendering

The web sidebar's history list renders grade chip per scan. Add a small flame indicator if the scan has any KEV findings (`SELECT 1 FROM findings WHERE scan_id=? AND kev=1 LIMIT 1`). `history.list_scans` already returns enough; add `kev_count` to its output.

---

## 9. LLM Tool-Argument Safety

`agent._exec_tool` currently does `int(args.get("level") or 2)` and `int(args.get("scan_id"))`. These crash on hallucinated args.

### 9.1 Helper

```python
def _as_int(v, default=None) -> int | None:
    if v is None: return default
    try: return int(str(v).strip())
    except (ValueError, TypeError): return default

def _as_str(v, default="") -> str:
    if v is None: return default
    return str(v).strip()
```

### 9.2 Apply in `_exec_tool`

Every `int(...)` / `str(...)` call wrapped. Bad input returns JSON error to the LLM:

```python
if name == "get_findings":
    scan_id = _as_int(args.get("scan_id"))
    if scan_id is None:
        return json.dumps({"error":"scan_id must be an integer"}), None
    ...
```

The LLM sees the error in its next turn and can correct (e.g. retry with a valid ID, or apologise to the user).

---

## 10. Multilingual via LLM-native Handling

### 10.1 Drop `_detect_lang`

Delete `_detect_lang`, `_SWAHILI_HINTS`, `_lang_instruction`. They forced English-or-Swahili based on a 23-word heuristic and degraded code-switching badly.

### 10.2 New system prompt instruction

Add to `_SYSTEM`:

```
LANGUAGE: Respond in the same language the user wrote in. If the user mixes
languages, prefer the one they wrote MORE of. Default to English if you cannot
tell. Always keep CVE IDs, IP addresses, port numbers, product names, and
version numbers in their original Latin form — do NOT translate
"CVE-2021-44228" or "192.168.1.1".
```

Llama-3.3-70b handles English, Swahili, French, Portuguese, Spanish, and several African languages natively. The system prompt instruction is enough.

### 10.3 Narrator and CVE-advice prompts already include explicit EN+SW output requirements (§6, §7). Those stay — the narrator/advice always produces both, and reports/UI pick the active language.

---

## 11. Prober Reliability

### 11.1 Current state

`prober/headers.py`, `prober/endpoints.py`, `prober/methods.py` each call `urllib.urlopen()` inside a broad `try: ... except Exception: pass` and return findings list. Network failure → empty list, indistinguishable from "host has no issues".

### 11.2 Change

Each prober function returns a dict instead of a list:

```python
{
    "status": "ok" | "unreachable" | "error",
    "findings": [ ... ],
    "error": "<exception text>"  # only if status='error'
}
```

`probe_http_service(host, port, scheme)` aggregates the three checks. If all three return `unreachable`, the service is reported as unreachable. If any returns findings, the service is probed.

### 11.3 Scan worker integration

`scan_helpers.http_probe_events` already iterates probe results. Adjust to:

- If `status='unreachable'`: emit an `http_unreachable` progress event ("80/tcp: HTTP probe failed — host did not respond") and skip findings.
- If `status='error'`: emit `http_error` event and skip.
- If `status='ok'`: emit findings as today.

The done event's `misconfigs` list contains only real findings (no unreachable rows).

---

## 12. WebSocket Chat Endpoint

### 12.1 Endpoint

`WS /ws/chat/{session_id}` — replaces (does NOT yet remove) the existing `POST /api/chat`.

### 12.2 Client → Server messages

```json
{"type": "user", "text": "scan 192.168.1.1"}
{"type": "interrupt"}                      // cancel in-flight LLM call
```

### 12.3 Server → Client messages

```json
{"type": "token", "text": "Star"}          // streamed tokens (currently Groq returns full response per call; this is a placeholder for future per-token streaming)
{"type": "tool_call", "name": "scan_host", "args": {...}}
{"type": "tool_result", "name": "scan_host", "summary": "Scan initiated for 192.168.1.1"}
{"type": "scan_intent", "scan_key": "<uuid>", "target": "192.168.1.1", "level": 2}
{"type": "complete", "text": "<full assistant message>"}
{"type": "error", "text": "<message>"}
```

When the AI's tool loop calls `scan_host`, the server creates a `scan_key`, stores it in `_pending` exactly like `POST /api/scan` does, and emits a `scan_intent` event. The frontend opens `WS /ws/scan/{scan_key}` per the existing scan flow. The chat WebSocket stays open in parallel — the user can continue chatting while the scan runs.

### 12.4 Streaming

Phase 1 uses Groq's non-streaming completion (single `complete` event per turn). The protocol accommodates token streaming, but its actual implementation is deferred to a follow-up so this spec stays focused.

### 12.5 Existing `POST /api/chat` deprecation

Kept until Phase 2 frontend lands. New code path (web UI) uses WebSocket; the CLI still calls `run_agent` directly. After Phase 2 ships and the WebSocket is exercised, delete `POST /api/chat`.

---

## 13. Session Management REST

```
GET    /api/sessions                       -> [{id,title,updated_at,created_at}]  (latest 20)
POST   /api/sessions                       -> {id}                                 (create empty)
GET    /api/sessions/{id}                  -> {id,title,updated_at,created_at,messages:[...]}
GET    /api/sessions/{id}/messages         -> [{role,content,tool_calls?,created_at}]
DELETE /api/sessions/{id}                  -> {deleted: id}                         (cascades to messages)
```

`POST /api/sessions` returns a session id; the frontend then opens `WS /ws/chat/{id}`. New sessions are anonymous — there's no auth model in Phase 1.

---

## 14. Backward Compatibility

| Surface | Impact |
|---|---|
| TUI (`aivas` interactive) | Call sites of `run_agent` updated to ignore the new third return value. Existing UX unchanged. |
| CLI scan (`aivas scan ... --narrate`) | Still calls `narrator.narrate` directly. Now also benefits from `cve_advice` cache when reports render. |
| Existing `POST /api/chat` | Kept and updated to use new memory (requires `session_id` query param; if absent, server creates one and returns it in response). Removed after Phase 2 lands. |
| Existing `POST /api/scan` + `WS /ws/scan/{key}` | Unchanged. |
| Report HTML/PDF rendering | Now also reads `cve_advice` table for tailored advice; falls back to legacy template. KEV pills appear on KEV findings. |

---

## 15. Testing Strategy

### Unit tests (Python, pytest)

| Module | Tests |
|---|---|
| `chat_memory.py` | create/get/list/delete session; load_history truncation rules (drop oldest pair, never split, never strand tool result); save_user/assistant/tool_result idempotency under concurrent inserts |
| `cve_advice.py` | get/put/warm_cache; warm_cache no-op on cache hits; bounded concurrency respected; api error doesn't poison cache |
| `scorer.py` | KEV multiplier applied; grade cap to C; non-KEV behaviour unchanged from current tests |
| `agent.py` | `_safe_args` returns defaults for garbage input; `run_agent` with `history=` correctly composes messages; `_exec_tool` returns JSON error for bad arg, never raises |
| `prober/*` | Each prober returns `status='unreachable'` on connect failure; `status='ok'` with real findings |
| `report_helpers.py` | `cve_fix` prefers stored fix, falls back to cve_advice cache, falls back to legacy template |

### Integration tests

| Scenario | Verification |
|---|---|
| Multi-turn chat | `POST /api/sessions` → 3 user/assistant turns via `POST /api/chat?session_id=X` → final assistant message references something from turn 1 |
| Web scan narration parity | Run web scan with valid Groq key → verify findings rows have non-empty `narration_en`, `narration_sw`, `fix_en`, `fix_sw` |
| KEV grade cap | Seed DB with one KEV CRITICAL on a host → grade ≤ C, score ≤ 75 |
| Tool arg safety | Force LLM (or stub) to return `scan_host(target="", level="best")` → tool returns JSON error, agent loop continues |
| Prober unreachable | Run HTTP probe against a closed port → done event has no misconfig for that port + scan log says "unreachable" |

### Manual smoke (supervisor demo prep)

- Multi-turn chat: "scan scanme.nmap.org" → "show me the worst CVE" → "explain that one to me in Swahili"
- KEV demo: scan a host with a known Log4j-bearing service; verify the grade caps at C even with one finding
- Per-CVE advice: two CVEs in different families both render distinct advice paragraphs in the HTML report

---

## 16. Migration / Rollout

1. `database/schema.py:create_schema` adds the three new tables idempotently.
2. Existing scans in the DB have empty narration fields; no backfill — those scans stay as-is. New web scans will populate going forward.
3. Existing `cve_advice` cache is empty; will warm naturally as scans run.
4. No environment variable changes. `GROQ_API_KEY` (or `api_key` config) is required for narration + cve_advice + chat — all three skip silently if absent and fall back to non-AI paths.

---

## 17. Open Questions (none blocking, resolve during implementation)

- Final wording of the LANGUAGE instruction in `_SYSTEM` — may need a 1-2 word adjustment based on observed model behaviour on Swahili turns
- Whether `update_title_if_unset` uses raw first-user-text or a one-shot LLM call to summarise — start with raw, upgrade later if titles feel ugly
- Whether sessions should auto-expire after 30 days — deferred decision until we see real usage volume

---

*Spec written 2026-06-30. Source of truth for Phase 1 backend changes. Phase 2 frontend redo depends on this landing first.*
