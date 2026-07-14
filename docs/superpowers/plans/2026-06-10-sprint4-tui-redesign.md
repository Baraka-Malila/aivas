# AIVAS Sprint 4 — TUI Redesign & AI Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all TUI crashes, wire the Groq AI narration, and redesign the UI (colors, progress flow, autocomplete, post-scan selection screen, first-run wizard) to match the locked Sprint 4 design spec.

**Architecture:** Split the monolithic `commands.py` (557 lines, violates 200-line limit) into focused modules. Add new `screens.py` for push_screen UI, `scan.py` for scan pipeline, `ai.py` for LLM dispatch, and `colors.py` for the palette. All TUI behavior stays in `aivas/tui/`. Tests cover every behavioral change.

**Tech Stack:** Python 3.10, Textual 8.2.7, Rich, Groq SDK (`groq` package), asyncio, sqlite3, nmap subprocess

---

## Design Spec Reference

All design decisions are locked in memory at `project_aivas_design_spec.md`. Key points:
- Accent color: `#4a9eff` (steel blue)
- CRITICAL `#e53935`, HIGH `#ff6d00`, MEDIUM `#fdd835`, LOW `#808080`
- [KEV] badge: bold white on red background
- Score line: single color by grade (green A/B, gold C, red D/F)
- No bold except section headers; color signals meaning only
- Selection UI: `app.push_screen()` full-screen (not modal overlay)
- Progress: step-lines in RichLog with animated spinner per stage
- Input bar: two `Rule` widgets + transparent `Input`, `>` prefix
- Autocomplete: OptionList with command+description pairs, Enter accepts
- KEV: auto-sync on startup (>7 days), no `/kev` command
- AI: Groq (`llama-3.1-8b-instant`), last 3 scans as context, no RAG
- Tables: `expand=True` for CVE + misconfig only

---

## File Map

| File | Action | Responsibility after |
|------|--------|----------------------|
| `aivas/tui/colors.py` | **Create** | Single source of truth for all color constants |
| `aivas/tui/app.py` | Modify | App layout, bindings, mounting, routing (keep ≤200 lines) |
| `aivas/tui/input_actions.py` | Modify | History, autocomplete (fix crashes, add descriptions) |
| `aivas/tui/commands.py` | Shrink | Registry, dispatcher, simple commands (help, clear, exit, copy, config, history, doctor) |
| `aivas/tui/scan.py` | **Create** | Scan pipeline, sudo nmap, validation, step-progress |
| `aivas/tui/ai.py` | **Create** | `_dispatch_ai`, narrate, session context |
| `aivas/tui/screens.py` | **Create** | `ScanResultScreen`, `SetupWizardScreen` (push_screen) |
| `aivas/formatting.py` | Modify | Apply new color palette, `expand=True` on CVE/misconfig tables |
| `tests/test_tui_checklist.py` | Modify | Update tests for new behavior |
| `tests/test_formatting.py` | Modify | Update color assertions |
| `docs/test-results/tui-checklist.md` | Modify | Clean and re-version for Round 5 |

---

## Task 1: Color palette module

**Files:**
- Create: `aivas/tui/colors.py`
- Modify: `aivas/formatting.py` (lines 1-15 — SEVERITY_COLORS dict)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_colors.py
from aivas.tui.colors import ACCENT, SEVERITY_COLORS, GRADE_COLOR, KEV_BADGE

def test_accent_is_blue():
    assert ACCENT == "#4a9eff"

def test_severity_has_four_keys():
    assert set(SEVERITY_COLORS.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

def test_critical_is_red():
    assert "e53935" in SEVERITY_COLORS["CRITICAL"]

def test_high_is_orange():
    assert "ff6d00" in SEVERITY_COLORS["HIGH"]

def test_grade_color_df_is_red():
    assert "e53935" in GRADE_COLOR("F")
    assert "e53935" in GRADE_COLOR("D")

def test_grade_color_ab_is_green():
    assert "4caf50" in GRADE_COLOR("A")
    assert "4caf50" in GRADE_COLOR("B")

def test_grade_color_c_is_gold():
    assert "fdd835" in GRADE_COLOR("C")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_colors.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'aivas.tui.colors'`

- [ ] **Step 3: Create `aivas/tui/colors.py`**

```python
"""Centralised color palette for AIVAS TUI.

Philosophy: color signals meaning, bold signals hierarchy — nothing else.
Two accent uses only: blue for interactive elements, red for danger.
"""

ACCENT = "#4a9eff"          # steel blue — prompt, commands, active items

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#e53935",  # red    — no bold
    "HIGH":     "#ff6d00",  # orange — distinct from red
    "MEDIUM":   "#fdd835",  # gold   — no bold
    "LOW":      "#808080",  # gray   — dim only
}

KEV_BADGE = "bold white on #e53935"    # badge style — "KEV" text only

SUCCESS = "#4caf50"   # green  — ✓ checks, all-clear
DANGER  = "#e53935"   # red    — errors (no bold)
MUTED   = "dim"       # timestamps, secondary info


def GRADE_COLOR(grade: str) -> str:
    """Return Rich color string for a scan grade."""
    if grade in ("A", "B"):
        return "#4caf50"
    if grade == "C":
        return "#fdd835"
    return "#e53935"   # D, F
```

- [ ] **Step 4: Update `aivas/formatting.py` to use the palette**

Replace lines 1–15 (old SEVERITY_COLORS):

```python
from rich.console import Console
from rich.table import Table
from rich.text import Text

from aivas.tui.colors import SEVERITY_COLORS, KEV_BADGE, ACCENT, GRADE_COLOR

_console = Console()
```

Replace the `cve_table` function entirely:

```python
def cve_table(title: str, rows: list[dict], desc_max: int = 80) -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("CVE ID", style="bold", min_width=16)
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Conf.", width=10)
    table.add_column("Description")   # no max_width — expand fills it
    for i, r in enumerate(rows, 1):
        sev = r.get("cvss_severity") or "N/A"
        sev_color = SEVERITY_COLORS.get(sev, "")
        cve_cell = Text(r["cve_id"])
        if r.get("kev"):
            cve_cell.append("\n")
            cve_cell.append(" KEV ", style=KEV_BADGE)
        sev_text = Text(sev, style=sev_color)
        score = r.get("cvss_score")
        table.add_row(
            str(i),
            cve_cell,
            str(score) if score is not None else "N/A",
            sev_text,
            r.get("confidence", "possible"),
            (r.get("description") or "")[:desc_max * 2],
        )
    return table
```

Replace `misconfig_table`:

```python
def misconfig_table(title: str, rows: list[dict], desc_max: int = 80) -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold", min_width=20)
    table.add_column("Description")
    table.add_column("Recommendation")
    for r in rows:
        sev = r.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(sev, "dim")
        table.add_row(
            Text(sev, style=sev_color),
            r.get("title", ""),
            (r.get("description") or "")[:desc_max * 2],
            (r.get("recommendation") or "")[:desc_max * 2],
        )
    return table
```

- [ ] **Step 5: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_colors.py tests/test_formatting.py -v
```
Expected: all PASS. Fix `test_cve_table_description_truncated` — update `desc_max` default from 60 to 80 in the test call.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/colors.py aivas/formatting.py tests/test_colors.py
git commit -m "feat: centralised color palette, expand CVE/misconfig tables"
```

---

## Task 2: Fix TAB crash + autocomplete redesign (command + description)

**Files:**
- Modify: `aivas/tui/input_actions.py` (line 86 — `self.focus_next()`)
- Modify: `aivas/tui/input_actions.py` (`_refresh_suggestions` — add descriptions)

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_tab_no_crash_repeated():
    """Tab pressed twice in a row must not crash."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        await pilot.press("slash")
        await pilot.pause(0.05)
        await pilot.press("tab")
        await pilot.pause(0.05)
        await pilot.press("tab")   # second tab — was crashing
        await pilot.pause(0.05)
        # no exception = pass

@pytest.mark.asyncio
async def test_tui_suggestion_shows_description():
    """Autocomplete options include the command description text."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/sc"
        await pilot.pause(0.1)
        ol = pilot.app.query_one("#suggestions")
        assert ol.display is True
        # At least one option text should contain "scan" description keyword
        option_texts = [str(ol.get_option_at_index(i).prompt)
                        for i in range(ol.option_count)]
        assert any("CVE" in t or "scan" in t.lower() for t in option_texts)

@pytest.mark.asyncio
async def test_tui_enter_accepts_suggestion():
    """Enter key accepts the highlighted suggestion."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/sc"
        await pilot.pause(0.1)
        ol = pilot.app.query_one("#suggestions")
        assert ol.display is True
        # navigate down to make sure an item is highlighted
        await pilot.press("down")
        await pilot.pause(0.05)
        await pilot.press("enter")
        await pilot.pause(0.05)
        assert inp.value.startswith("/")
        assert not ol.display
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_tab_no_crash_repeated tests/test_tui_checklist.py::test_tui_suggestion_shows_description -v
```
Expected: FAIL

- [ ] **Step 3: Fix `action_accept_or_cycle` (TAB crash fix)**

In `aivas/tui/input_actions.py`, replace line 86:
```python
    # OLD: self.focus_next()
    # NEW:
    def action_accept_or_cycle(self) -> None:
        inp = self.query_one("#cmd-input", Input)
        if inp.has_focus and self._accept_suggestion():
            return
        # Tab with no suggestions: do nothing (input keeps focus)
```

- [ ] **Step 4: Add Enter-to-accept binding in input_actions.py**

The `on_option_list_option_selected` handler already exists and fires on mouse click. We need the OptionList to also respond when the user presses Enter/Down while it's visible. Add a binding and handler:

In `AIVASApp.BINDINGS` (app.py), the existing `Binding("tab", "accept_or_cycle", ...)` handles Tab. We also need Down-when-suggestions-visible to move into the list. Update `action_history_next` in input_actions.py:

```python
def action_history_next(self) -> None:
    ol = self.query_one("#suggestions", OptionList)
    inp = self.query_one("#cmd-input", Input)
    # If suggestions visible and Down is pressed, focus the list
    if ol.display and ol.option_count and inp.has_focus:
        ol.focus()
        return
    if not inp.has_focus:
        return
    if self._history_idx > 0:
        self._history_idx -= 1
        inp.value = self._cmd_history[self._history_idx]
        inp.cursor_position = len(inp.value)
    elif self._history_idx == 0:
        self._history_idx = -1
        inp.value = ""
```

- [ ] **Step 5: Format suggestions with command + description**

Replace `_refresh_suggestions` in `input_actions.py`:

```python
def _refresh_suggestions(self, text: str) -> None:
    from rich.text import Text
    from aivas.tui.colors import ACCENT
    if not text.startswith("/") or (len(text) > 1 and " " in text[1:]):
        self._hide_suggestions()
        return
    typed = text[1:].lower()
    matches = [
        (name, usage, desc)
        for name, (usage, desc) in _cmds.REGISTRY.items()
        if not typed or (name.startswith(typed) and name != typed)
    ]
    ol = self.query_one("#suggestions", OptionList)
    ol.clear_options()
    self._suggestions = []
    if matches:
        from textual.widgets.option_list import Option
        for name, usage, desc in matches:
            prompt = Text()
            prompt.append(f"/{name:<12}", style=f"bold {ACCENT}")
            prompt.append(f"  {desc}", style="dim")
            ol.add_option(Option(prompt, id=name))
            self._suggestions.append(f"/{name}")
        ol.display = True
    else:
        ol.display = False
```

Update `_accept_suggestion` to use the OptionList's selected id:

```python
def _accept_suggestion(self) -> bool:
    ol = self.query_one("#suggestions", OptionList)
    if not ol.display or not ol.option_count:
        return False
    idx = ol.highlighted if ol.highlighted is not None else 0
    if idx < len(self._suggestions):
        inp = self.query_one("#cmd-input", Input)
        inp.value = self._suggestions[idx] + " "
        inp.cursor_position = len(inp.value)
    self._hide_suggestions()
    inp = self.query_one("#cmd-input", Input)
    inp.focus()
    return True
```

Also add option_list key handler — when OptionList is focused and Enter pressed, accept:

```python
def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
    idx = event.option_index
    if idx < len(self._suggestions):
        inp = self.query_one("#cmd-input", Input)
        inp.value = self._suggestions[idx] + " "
        inp.cursor_position = len(inp.value)
        inp.focus()
    self._hide_suggestions()
```

- [ ] **Step 6: Update OptionList CSS in app.py to use accent color highlight**

In `_CSS` in `app.py`, update the `#suggestions` block:

```css
#suggestions {
    max-height: 12;
    background: $surface-darken-1;
    display: none;
    padding: 0;
    border: none;
}

OptionList > .option-list--option-highlighted {
    background: $surface-darken-3;
    color: #4a9eff;
}
```

- [ ] **Step 7: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py -k "tab or suggestion" -v
```
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/input_actions.py aivas/tui/app.py
git commit -m "fix: TAB crash, autocomplete shows command descriptions, Enter accepts"
```

---

## Task 3: Fix crash bugs (HS3 markup escape + save_scan args)

**Files:**
- Modify: `aivas/tui/app.py` (line 124 — error handler)
- Modify: `aivas/tui/commands.py` (line 418 — save_scan call)

- [ ] **Step 1: Write the failing tests**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_history_show_no_crash_with_markup_in_description():
    """History show must not crash when CVE descriptions contain markup chars."""
    import sqlite3
    from aivas.database.schema import init_db
    from aivas.history import save_scan
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    # Insert a finding whose description contains Rich markup-like text
    findings = [{
        "cve_id": "CVE-2021-0001",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "confidence": "probable",
        "description": "Buffer overflow in [kernel] module [/proc] path",  # has [/]
        "host": "192.168.1.1",
    }]
    save_scan(conn, "192.168.1.1", findings)
    app = _make_spy_app(conn=conn)
    async with app.run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/history show 1"
        await pilot.press("enter")
        await pilot.pause(0.2)
        # Must not crash — output pane still exists
        assert pilot.app.query_one("#output") is not None

def test_save_scan_no_extra_args():
    """save_scan called with correct signature — no TypeError."""
    import sqlite3
    from aivas.database.schema import init_db
    from aivas.history import save_scan
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    findings = [{"cve_id": "CVE-0001", "cvss_score": 7.0,
                 "cvss_severity": "HIGH", "confidence": "probable",
                 "host": "192.168.1.1"}]
    scan_id = save_scan(conn, "192.168.1.1", findings)   # no extra args
    assert scan_id > 0
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_history_show_no_crash_with_markup_in_description tests/test_tui_checklist.py::test_save_scan_no_extra_args -v
```

- [ ] **Step 3: Fix the error handler in `app.py` (lines 121-127)**

```python
    except Exception as exc:
        self.set_scan_idle()
        self._scan_task = None
        from rich.markup import escape
        log.write(
            f"[bold {ACCENT}]Error:[/bold {ACCENT}] {type(exc).__name__}: "
            + escape(str(exc))
            + "\n[dim]The TUI is still running.[/dim]"
        )
```

Add `from aivas.tui.colors import ACCENT` at top of `app.py`.

- [ ] **Step 4: Escape CVE content in history display (`commands.py` `_cmd_history`)**

In `_cmd_history`, replace the `elif sub == "show"` block:

```python
    elif sub == "show" and len(parts) >= 2:
        try:
            sid = int(parts[1])
        except ValueError:
            app.tui_print("[red]Usage:[/red] /history show <id>")
            return
        from aivas.history import get_scan_findings
        from aivas.formatting import cve_table
        from rich.markup import escape
        findings = get_scan_findings(app.conn, sid)
        if not findings:
            app.tui_print(f"[yellow]Scan #{sid} not found.[/yellow]")
            return
        # Sanitise descriptions — they may contain Rich markup-like characters
        safe = []
        for f in findings:
            s = dict(f)
            s["description"] = escape(s.get("description") or "")
            safe.append(s)
        app.tui_print(cve_table(f"Scan #{sid} Findings", safe))
```

- [ ] **Step 5: Fix `save_scan` call in `commands.py` (line 418)**

```python
        # OLD: save_scan(app.conn, target, findings, s["score"], s["grade"])
        # NEW:
        from aivas.history import save_scan
        save_scan(app.conn, target, findings)
        app.tui_print("[dim]Scan saved to history (/history list)[/dim]")
```

- [ ] **Step 6: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_history_show_no_crash_with_markup_in_description tests/test_tui_checklist.py::test_save_scan_no_extra_args -v
```
Expected: both PASS

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/app.py aivas/tui/commands.py
git commit -m "fix: escape markup in error handler and history display, fix save_scan args"
```

---

## Task 4: Fix SC7/QD3 — sudo nmap stdout capture

**Files:**
- Modify: `aivas/tui/commands.py` (lines 258–302 — `_run_nmap_sudo`)

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_tui_checklist.py
import subprocess
from unittest.mock import patch, MagicMock

def test_sudo_nmap_uses_stdout_not_tempfile():
    """_run_nmap_sudo must use -oX - (stdout) not a tempfile."""
    from aivas.tui.commands import _run_nmap_sudo
    import inspect
    src = inspect.getsource(_run_nmap_sudo)
    assert '"-oX"' in src or "'-oX'" in src
    assert '"-"' in src or "'-'" in src
    # Must NOT pre-create a NamedTemporaryFile
    assert "NamedTemporaryFile" not in src
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_sudo_nmap_uses_stdout_not_tempfile -v
```

- [ ] **Step 3: Rewrite `_run_nmap_sudo` in `commands.py` (replace lines 258–302)**

```python
async def _run_nmap_sudo(app: "AIVASApp", target: str, scripts: str,
                          udp: bool, timeout: int = 300) -> str:
    """Pause TUI, run sudo nmap with stdout XML capture, return XML string.

    Uses -oX - to write XML to stdout — avoids the nmap security check
    that refuses to write to files not owned by the running user (root).
    sudo prompts on /dev/tty so stdout capture does not interfere.
    """
    import sys
    import subprocess
    import shutil

    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = ["sudo", nmap_bin, "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if scripts:
        cmd += ["--script", scripts]

    with app.suspend():
        sys.stdout.write(
            "\n[AIVAS] UDP scan requires root privileges.\n"
            "(One-time fix to avoid this prompt: "
            f"sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin})\n\n"
        )
        sys.stdout.flush()
        try:
            result = subprocess.run(
                cmd,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap timed out after {timeout}s.")

    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited {result.returncode} — "
            "sudo password wrong, denied, or nmap not found?"
        )
    xml = result.stdout.decode("utf-8", errors="replace")
    if not xml.strip():
        raise RuntimeError("nmap produced no output (check sudo permissions).")
    return xml
```

- [ ] **Step 4: Run test**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_sudo_nmap_uses_stdout_not_tempfile -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/commands.py
git commit -m "fix: sudo nmap uses -oX - stdout capture, avoids file ownership error"
```

---

## Task 5: Fix ESC cancel (kill subprocess) + lock input during scan

**Files:**
- Modify: `aivas/tui/app.py` (`set_scan_running`, `set_scan_idle`, `action_cancel_or_blur`)
- Modify: `aivas/tui/commands.py` (`_run_scan_pipeline` — store subprocess handle)

- [ ] **Step 1: Write the failing tests**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_input_disabled_while_scanning():
    """Input must be disabled while a scan is running."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        pilot.app.set_scan_running("192.168.1.1")
        inp = pilot.app.query_one("#cmd-input")
        assert inp.disabled is True

@pytest.mark.asyncio
async def test_tui_input_enabled_after_scan():
    """Input must be re-enabled after scan finishes."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        pilot.app.set_scan_running("192.168.1.1")
        pilot.app.set_scan_idle()
        inp = pilot.app.query_one("#cmd-input")
        assert inp.disabled is False
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_input_disabled_while_scanning tests/test_tui_checklist.py::test_tui_input_enabled_after_scan -v
```

- [ ] **Step 3: Add `_scan_proc` to `app.py` `__init__` and update scan state methods**

In `app.py` `__init__`, add:
```python
self._scan_proc: "subprocess.Popen | None" = None
```

Update `set_scan_running`:
```python
def set_scan_running(self, target: str = "") -> None:
    inp = self.query_one("#cmd-input", Input)
    inp.disabled = True
    self._hide_suggestions()
    lbl = self.query_one("#scan-status", Label)
    lbl.update(f"  Scanning {target}…  (ESC to cancel)")
    lbl.display = True
```

Update `set_scan_idle`:
```python
def set_scan_idle(self) -> None:
    self.query_one("#scan-status", Label).display = False
    self.query_one("#cmd-input", Input).disabled = False
    self.query_one("#cmd-input", Input).focus()
```

Update `action_cancel_or_blur`:
```python
def action_cancel_or_blur(self) -> None:
    if self._scan_task is not None and not self._scan_task.done():
        self._scan_task.cancel()
        # Also kill the nmap subprocess if it's still running
        if self._scan_proc is not None:
            try:
                self._scan_proc.kill()
            except OSError:
                pass
            self._scan_proc = None
        self.set_scan_idle()
        self.tui_print("[dim]Scan cancelled.[/dim]")
    else:
        self.query_one("#cmd-input", Input).blur()
```

- [ ] **Step 4: Store subprocess handle in `commands.py` `_run_scan_pipeline`**

In `_run_scan_pipeline`, after `app.set_scan_running(target)`, update the non-sudo path to store the proc. Wrap `run_scan` to store the proc on `app._scan_proc`. The simplest way: add a `_run_scan_with_handle` wrapper in commands.py:

```python
async def _run_scan_with_handle(app: "AIVASApp", target: str,
                                 scripts: str, udp: bool, os_detect: bool) -> str:
    """Run nmap, storing the subprocess on app._scan_proc for ESC cancellation."""
    import subprocess
    import tempfile
    import os
    from aivas.scanner.nmap_runner import build_nmap_cmd  # existing helper

    cmd = build_nmap_cmd(target, scripts=scripts, udp=udp, os_detect=os_detect)
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        tmpfile = f.name
    cmd += ["-oX", tmpfile]
    try:
        proc = subprocess.Popen(cmd)
        app._scan_proc = proc
        await asyncio.to_thread(proc.wait)
        app._scan_proc = None
        if proc.returncode != 0:
            raise RuntimeError(f"nmap exited {proc.returncode}")
        with open(tmpfile) as fh:
            return fh.read()
    finally:
        app._scan_proc = None
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
```

Check if `build_nmap_cmd` exists: `grep -r "build_nmap_cmd\|def run_scan" /home/cyberpunk/aivas/aivas/scanner/`. If it doesn't, use the existing `run_scan` and wrap it differently — the key is storing `app._scan_proc = proc`.

**Note:** If `run_scan` in `aivas/scanner/__init__.py` uses `subprocess.run` internally, extract the Popen approach. Read `aivas/scanner/__init__.py` before implementing and adapt accordingly.

- [ ] **Step 5: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_input_disabled_while_scanning tests/test_tui_checklist.py::test_tui_input_enabled_after_scan -v
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/app.py aivas/tui/commands.py
git commit -m "fix: lock input during scan, ESC kills nmap subprocess"
```

---

## Task 6: Flag validation + split commands.py

**Files:**
- Modify: `aivas/tui/commands.py` (shrink to ≤200 lines — move scan logic out)
- Create: `aivas/tui/scan.py` (scan pipeline, validation, sudo logic — extracted)

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_unknown_flag_shows_error():
    """Unknown flags like --badflagnobody must show an error, not scan."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/scan 192.168.1.1 --badflagnobody"
        await pilot.press("enter")
        await pilot.pause(0.1)
        out = " ".join(app._spy_output)
        assert "unknown" in out.lower() or "invalid" in out.lower() or "flag" in out.lower()
        # Must NOT have started a scan
        assert "scanning" not in out.lower()
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_tui_unknown_flag_shows_error -v
```

- [ ] **Step 3: Create `aivas/tui/scan.py`**

Move `_nmap_needs_sudo`, `_run_nmap_sudo`, `_bad_ip`, `_resolves`, `_run_scan_pipeline`, `_run_scan_with_handle` from `commands.py` into `scan.py`. At the top of `scan.py`:

```python
"""Scan pipeline: validation, nmap execution, CVE correlation, output."""
from __future__ import annotations

import asyncio
import re
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp

_IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?$')
_KNOWN_FLAGS = {"--level", "--udp"}
```

Add flag validation in `_cmd_scan` (stays in `commands.py` as a thin dispatcher, calls `scan.run_scan_cmd`):

In `scan.py`, add this check inside the scan arg parser:
```python
    i = 1
    while i < len(parts):
        if parts[i] == "--level" and i + 1 < len(parts):
            try:
                level = int(parts[i + 1])
                if level not in (1, 2, 3):
                    raise ValueError
            except ValueError:
                return None, None, None, f"--level must be 1, 2, or 3"
            i += 2
        elif parts[i] == "--udp":
            udp = True
            i += 1
        elif parts[i].startswith("--"):
            return None, None, None, f"Unknown flag: {parts[i]!r}. Valid flags: --level 1-3, --udp"
        else:
            i += 1
```

- [ ] **Step 4: Update `commands.py` — shrink to ≤200 lines**

After moving scan functions to `scan.py`, `commands.py` should contain only:
- `REGISTRY` dict
- `handle()` dispatcher
- `_cmd_help`, `_cmd_clear`, `_cmd_exit`, `_cmd_copy`
- `_cmd_doctor`, `_cmd_config`, `_cmd_history`
- `_cmd_scan`, `_cmd_quick`, `_cmd_deep` (thin wrappers that call `scan.py`)
- `_HANDLERS` dict

Import from scan.py: `from .scan import run_scan_pipeline, parse_scan_args`

- [ ] **Step 5: Run all tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py tests/test_formatting.py -v
```
Expected: all PASS

- [ ] **Step 6: Verify file sizes**

```bash
wc -l /home/cyberpunk/aivas/aivas/tui/commands.py /home/cyberpunk/aivas/aivas/tui/scan.py
```
Both must be ≤200 lines.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/commands.py aivas/tui/scan.py
git commit -m "refactor: extract scan pipeline to scan.py, validate flags, commands.py ≤200 lines"
```

---

## Task 7: Input bar redesign (two Rules + transparent, `>` prefix)

**Files:**
- Modify: `aivas/tui/app.py` (`compose()`, `_CSS`)

- [ ] **Step 1: Write the test**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_input_has_no_box_border():
    """Input widget must have no box border (transparent style)."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        # Check the CSS class — must have 'transparent-input' class applied
        assert "transparent-input" in inp.classes or inp.styles.border_top[0] in ("none", "")
```

- [ ] **Step 2: Update `compose()` in `app.py`**

```python
from textual.widgets import Footer, Header, Input, Label, OptionList, RichLog, Rule

def compose(self) -> ComposeResult:
    yield Header(show_clock=True)
    yield RichLog(id="output", markup=True, highlight=True, wrap=True)
    yield OptionList(id="suggestions")
    yield Rule(id="rule-top")
    from textual.app import ComposeResult
    from textual.containers import Horizontal
    yield Horizontal(
        Label("> ", id="prompt-label"),
        Input(
            placeholder="type a command or ask me to scan something",
            id="cmd-input",
        ),
        id="input-row",
    )
    yield Rule(id="rule-bottom")
    yield Label("", id="scan-status")
    yield Footer()
```

- [ ] **Step 3: Update `_CSS` in `app.py`**

```python
_CSS = """
Screen { layout: vertical; background: $surface; }

#output {
    height: 1fr;
    border: none;
    padding: 1 2;
    scrollbar-gutter: stable;
}

#suggestions {
    max-height: 12;
    background: $surface-darken-1;
    display: none;
    border: none;
    padding: 0;
}

OptionList > .option-list--option-highlighted {
    background: $surface-darken-3;
}

#rule-top, #rule-bottom {
    color: $panel;
    margin: 0;
    height: 1;
}

#input-row {
    height: auto;
    background: $surface;
    padding: 0;
}

#prompt-label {
    width: 3;
    padding: 0 0 0 1;
    color: #4a9eff;
    text-style: bold;
}

#cmd-input {
    background: $surface;
    border: none;
    padding: 0;
    width: 1fr;
    color: $text;
}

#cmd-input:focus { border: none; }

#cmd-input.cmd { color: #4a9eff; }

#scan-status {
    height: 1;
    padding: 0 2;
    color: #fdd835;
    display: none;
}
"""
```

- [ ] **Step 4: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py -v --tb=short
```
Expected: all PASS. If `test_tui_input_has_no_box_border` fails, adjust the CSS check.

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/app.py
git commit -m "feat: redesign input bar with two Rules, transparent bg, blue > prefix"
```

---

## Task 8: Step-line progress in RichLog

**Files:**
- Create: `aivas/tui/progress.py`
- Modify: `aivas/tui/scan.py` (use StepProgress in pipeline)

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_tui_sc8_invalid_ip_step_no_progress():
    """Invalid IP must show error without showing any progress steps."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/scan 999.999.999.999"
        await pilot.press("enter")
        await pilot.pause(0.15)
        out = " ".join(app._spy_output)
        assert "invalid" in out.lower() or "octet" in out.lower()
        assert "port discovery" not in out.lower()

def test_step_progress_output_format():
    """StepProgress outputs step start and complete lines."""
    from aivas.tui.progress import StepProgress
    output = []
    class FakeApp:
        def tui_print(self, msg):
            output.append(str(msg))
    p = StepProgress(FakeApp())
    p.step("Port discovery")
    p.done("Port discovery", "3 open ports")
    combined = " ".join(output)
    assert "Port discovery" in combined
    assert "3 open ports" in combined
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_step_progress_output_format -v
```

- [ ] **Step 3: Create `aivas/tui/progress.py`**

```python
"""Step-line progress reporting for the scan pipeline.

Each stage prints a start line, then overwrites with a done line.
Since RichLog appends (cannot overwrite), we print both lines sequentially.
The start line uses a spinner char; the done line uses ✓.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp

_SPINNER = "·"


class StepProgress:
    """Thin wrapper that prints step start + done lines to the TUI output."""

    def __init__(self, app: "AIVASApp") -> None:
        self._app = app

    def step(self, name: str) -> None:
        """Print a 'starting' line for this stage."""
        self._app.tui_print(
            f"  [{_SPINNER}] [dim]{name}...[/dim]"
        )

    def done(self, name: str, detail: str = "") -> None:
        """Print a 'completed' line with optional detail."""
        detail_str = f"  [dim]{detail}[/dim]" if detail else ""
        self._app.tui_print(
            f"  [#4caf50]✓[/#4caf50] {name}{detail_str}"
        )

    def fail(self, name: str, reason: str) -> None:
        """Print a 'failed' line."""
        self._app.tui_print(
            f"  [#e53935]✗[/#e53935] {name}  [dim]{reason}[/dim]"
        )
```

- [ ] **Step 4: Use StepProgress in `_run_scan_pipeline` (in `scan.py`)**

Replace the existing print statements in `_run_scan_pipeline`:

```python
from .progress import StepProgress

async def _run_scan_pipeline(app: "AIVASApp", target: str,
                              level: int, udp: bool = False) -> None:
    # ... existing validation ...
    prog = StepProgress(app)

    app.tui_print(
        f"\n  Scanning [bold]{target}[/bold]"
        f"  [dim](level {level}{', UDP' if udp else ''})[/dim]\n"
    )
    app.set_scan_running(target)
    await asyncio.sleep(0)

    app._scan_task = asyncio.current_task()
    use_sudo = await _nmap_needs_sudo(udp)

    prog.step("Port discovery + service detection")
    try:
        if use_sudo:
            xml = await _run_nmap_sudo(app, target, scripts_for_level(level), udp)
        else:
            xml = await _run_scan_with_handle(
                app, target, scripts=scripts_for_level(level),
                udp=udp, os_detect=True,
            )
    except asyncio.CancelledError:
        prog.fail("Port discovery", "cancelled")
        app.set_scan_idle()
        return
    except RuntimeError as exc:
        prog.fail("Port discovery", str(exc))
        app.set_scan_idle()
        return
    finally:
        app._scan_task = None

    try:
        services = parse_nmap_xml(xml)
    except Exception:
        app.tui_print("[#e53935]Parse error:[/#e53935] nmap returned unexpected output.")
        app.set_scan_idle()
        return

    prog.done("Port discovery + service detection",
              f"{len(services)} service(s) found" if services else "no open ports")

    if not services:
        app.tui_print("  [dim]No open services found.[/dim]")
        app.set_scan_idle()
        return

    prog.step("CVE correlation")
    os_hint = services[0].get("os_family") or None
    findings = [f for f in correlate(app.conn, services, os_hint=os_hint)
                if f.get("confidence") in ("probable", "confirmed")][:30]
    prog.done("CVE correlation",
              f"{len(findings)} CVE(s) matched" if findings else "no matches")

    # HTTP config checks
    prog.step("Configuration checks")
    misconfigs: list[dict] = []
    for svc in services:
        is_http = svc.get("service", "") in ("http", "https", "ssl") or (
            svc.get("port") in (80, 443, 8080, 8443))
        if is_http:
            mc = await asyncio.to_thread(
                probe_http_service, svc["host"], svc["port"],
                "ssl" in svc.get("service", ""))
            misconfigs.extend(mc)
    prog.done("Configuration checks",
              f"{len(misconfigs)} issue(s)" if misconfigs else "none")

    app.set_scan_idle()

    # Store results on app for post-scan screen
    app._last_findings = findings
    app._last_misconfigs = misconfigs
    app._last_target = target

    # Show compact summary then post-scan screen
    from .ai import compute_score_summary
    s = score_findings(findings)
    grade_color = GRADE_COLOR(s["grade"])
    app.tui_print(
        f"\n  ─────────────────────────────────────────────\n"
        f"  Score  [{grade_color}]{s['score']}/100  Grade {s['grade']}[/{grade_color}]"
        f"  ·  [dim]{s['total']} findings[/dim]\n"
        f"  ─────────────────────────────────────────────\n"
    )

    # Auto-save
    from aivas.history import save_scan
    try:
        save_scan(app.conn, target, findings)
    except Exception:
        pass

    # Push post-scan selection screen
    from .screens import ScanResultScreen
    await app.push_screen(
        ScanResultScreen(target, s, findings, misconfigs),
    )
```

- [ ] **Step 5: Add `_last_findings`, `_last_misconfigs`, `_last_target` to `app.py` `__init__`**

```python
self._last_findings: list[dict] = []
self._last_misconfigs: list[dict] = []
self._last_target: str = ""
```

- [ ] **Step 6: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_step_progress_output_format tests/test_tui_checklist.py::test_tui_sc8_invalid_ip_step_no_progress -v
```
Expected: PASS

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/progress.py aivas/tui/scan.py aivas/tui/app.py
git commit -m "feat: step-line scan progress (port/service/CVE/config stages)"
```

---

## Task 9: Post-scan selection screen + first-run wizard

**Files:**
- Create: `aivas/tui/screens.py`

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_tui_checklist.py

@pytest.mark.asyncio
async def test_scan_result_screen_renders():
    """ScanResultScreen must show title, grade, and three options."""
    from aivas.tui.screens import ScanResultScreen
    from textual.app import App
    class TestApp(App):
        def on_mount(self):
            score = {"score": 32, "grade": "D", "total": 5, "sev_counts": {}}
            self.push_screen(ScanResultScreen("192.168.1.1", score, [], []))
    async with TestApp().run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        screen_text = pilot.app.screen.query("Label,Static")
        texts = [str(w.renderable) for w in screen_text]
        combined = " ".join(texts)
        assert "192.168.1.1" in combined or "Scan complete" in combined
        assert "report" in combined.lower() or "narration" in combined.lower()
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_scan_result_screen_renders -v
```

- [ ] **Step 3: Create `aivas/tui/screens.py`**

```python
"""Push-screens for AIVAS: post-scan result choice and first-run setup wizard.

These are full-screen overlays (app.push_screen) — not floating modals.
The main screen is paused underneath. On dismiss, control returns to main.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Label, RadioButton, RadioSet, Static, Input, Button, Rule

from .colors import ACCENT, GRADE_COLOR, DANGER


class ScanResultScreen(Screen):
    """Post-scan choice: view full report / AI narration / skip."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip", show=False),
        Binding("enter",  "confirm",      "Confirm", priority=True),
    ]

    CSS = """
    ScanResultScreen {
        align: center middle;
        background: $surface;
        padding: 2 4;
    }
    #scan-summary { margin-bottom: 1; }
    #scan-choices { margin-top: 1; }
    #hint-bar { dock: bottom; color: $text-muted; }
    """

    def __init__(self, target: str, score: dict,
                 findings: list[dict], misconfigs: list[dict]) -> None:
        super().__init__()
        self._target = target
        self._score = score
        self._findings = findings
        self._misconfigs = misconfigs

    def compose(self) -> ComposeResult:
        g = self._score.get("grade", "?")
        s = self._score.get("score", 0)
        total = self._score.get("total", 0)
        gc = GRADE_COLOR(g)
        yield Rule()
        yield Static(
            f"[bold]Scan complete[/bold]  ·  {self._target}\n"
            f"Grade [{gc}]{g}[/{gc}]  ·  {s}/100  ·  [dim]{total} findings[/dim]",
            id="scan-summary",
        )
        yield Rule()
        yield Static("\nWhat would you like to do?\n")
        yield RadioSet(
            RadioButton("View full CVE report", id="report", value=True),
            RadioButton("AI narration  (top 5, English + Swahili)", id="narrate"),
            RadioButton("Save and continue", id="skip"),
            id="scan-choices",
        )
        yield Static(
            "\n[dim]↑↓ navigate  ·  Enter confirm  ·  Esc skip[/dim]",
            id="hint-bar",
        )

    def action_confirm(self) -> None:
        rs = self.query_one(RadioSet)
        choice = rs.pressed_button.id if rs.pressed_button else "skip"
        self.dismiss(choice)

    def action_dismiss_skip(self) -> None:
        self.dismiss("skip")

    def on_screen_resume(self) -> None:
        self.query_one(RadioSet).focus()


class SetupWizardScreen(Screen):
    """First-run setup: provider, API key, language."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip", show=False),
        Binding("ctrl+s", "save_config",  "Save", priority=True),
    ]

    CSS = """
    SetupWizardScreen {
        background: $surface;
        padding: 2 4;
    }
    #wizard-title { margin-bottom: 1; }
    #api-key-input { margin-top: 1; width: 50; }
    #hint-bar { dock: bottom; color: $text-muted; }
    """

    def compose(self) -> ComposeResult:
        yield Rule()
        yield Static("[bold]Welcome to AIVAS — Quick Setup[/bold]\n"
                     "[dim]Set up once, scan forever.[/dim]\n",
                     id="wizard-title")
        yield Static("[bold]AI Provider:[/bold]")
        yield RadioSet(
            RadioButton("Groq  (cloud, fast, free tier)", id="groq", value=True),
            RadioButton("Ollama  (local, private)",       id="ollama"),
            id="provider-set",
        )
        yield Static("\n[bold]API Key:[/bold]")
        yield Input(placeholder="sk-... or groq API key", password=True,
                    id="api-key-input")
        yield Static("\n[bold]Output Language:[/bold]")
        yield RadioSet(
            RadioButton("English",           id="en", value=True),
            RadioButton("Swahili",           id="sw"),
            RadioButton("Both (EN + SW)",    id="both"),
            id="lang-set",
        )
        yield Rule()
        yield Static("[dim]Tab next field  ·  Ctrl+S save  ·  Esc skip[/dim]",
                     id="hint-bar")

    def action_save_config(self) -> None:
        from aivas import config as _config
        provider_rs = self.query_one("#provider-set", RadioSet)
        lang_rs = self.query_one("#lang-set", RadioSet)
        api_key = self.query_one("#api-key-input", Input).value.strip()
        provider = provider_rs.pressed_button.id if provider_rs.pressed_button else "groq"
        lang = lang_rs.pressed_button.id if lang_rs.pressed_button else "en"
        if api_key:
            _config.save("api_key", api_key)
        _config.save("provider", provider)
        _config.save("lang", lang)
        self.dismiss({"provider": provider, "lang": lang, "has_key": bool(api_key)})

    def action_dismiss_skip(self) -> None:
        self.dismiss(None)

    def on_screen_resume(self) -> None:
        self.query_one("#provider-set", RadioSet).focus()
```

- [ ] **Step 4: Wire ScanResultScreen result back into scan flow**

In `_run_scan_pipeline` (scan.py), after `await app.push_screen(ScanResultScreen(...))`, add the callback:

In `app.py`, add the push_screen callback method:

```python
async def _handle_scan_result_choice(self, choice: str) -> None:
    """Called when ScanResultScreen is dismissed."""
    from aivas.formatting import cve_table, misconfig_table
    if choice == "report":
        if self._last_findings:
            self.tui_print(cve_table("Vulnerability Findings", self._last_findings))
        if self._last_misconfigs:
            self.tui_print(misconfig_table("Configuration Issues", self._last_misconfigs))
    elif choice == "narrate":
        await self._run_narration(self._last_findings[:5])
```

Wire in scan.py by using `app.push_screen_wait` (async version) or callback:
```python
    choice = await app.push_screen_wait(
        ScanResultScreen(target, s, findings, misconfigs)
    )
    await app._handle_scan_result_choice(choice)
```

- [ ] **Step 5: Wire first-run wizard into `app.py` `on_mount`**

```python
async def on_mount(self) -> None:
    self.query_one("#output", RichLog).write(_BANNER)
    self.query_one("#cmd-input", Input).focus()
    # First-run: show setup wizard if no API key configured
    from aivas import config as _config
    from .screens import SetupWizardScreen
    cfg = _config.load()
    if not cfg.get("api_key"):
        result = await self.push_screen_wait(SetupWizardScreen())
        if result:
            self.tui_print(
                f"[dim]Setup saved. Provider: {result['provider']}, "
                f"Language: {result['lang']}[/dim]"
            )
```

- [ ] **Step 6: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_scan_result_screen_renders -v
```

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/screens.py aivas/tui/app.py aivas/tui/scan.py
git commit -m "feat: post-scan ScanResultScreen and first-run SetupWizardScreen"
```

---

## Task 10: AI wiring — free text, narration, session context

**Files:**
- Create: `aivas/tui/ai.py`
- Modify: `aivas/tui/commands.py` (remove `/ask` and `/kev` from REGISTRY, remove `_cmd_ask`)
- Modify: `aivas/tui/app.py` (`_route`, `_run_narration`, `_handle_scan_result_choice`)

- [ ] **Step 1: Write the failing tests**

```python
# Add to tests/test_tui_checklist.py

def test_ai_dispatch_no_key_shows_helpful_message():
    """Free text with no API key shows a helpful message, not an error."""
    from aivas.tui import ai as _ai
    output = []
    class FakeApp:
        def tui_print(self, m): output.append(str(m))
        _scan_history = []
    import asyncio
    asyncio.run(_ai.dispatch(FakeApp(), "hello there", api_key=None))
    combined = " ".join(output)
    assert "api key" in combined.lower() or "key" in combined.lower()
    assert "scan" in combined.lower()

def test_ai_session_context_includes_last_scan():
    """build_context must include the last scan target in the returned string."""
    from aivas.tui.ai import build_context
    history = [
        {"target": "192.168.1.1", "score": 32, "grade": "D",
         "top_cves": ["CVE-2021-41773"]},
    ]
    ctx = build_context(history)
    assert "192.168.1.1" in ctx
    assert "CVE-2021-41773" in ctx
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_ai_dispatch_no_key_shows_helpful_message tests/test_tui_checklist.py::test_ai_session_context_includes_last_scan -v
```

- [ ] **Step 3: Create `aivas/tui/ai.py`**

```python
"""AI dispatch: intent parsing, narration, session context.

Free text (no /) routes here from app._route.
Provider: Groq (llama-3.1-8b-instant) from .env GROQ_API_KEY.
Context: last 3 session scans as structured text — no RAG.
Scope: scan intent only + explain results. Not a general chatbot.
"""
from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp

_SYSTEM_PROMPT = """\
You are AIVAS, a network security scanner assistant for small businesses in Tanzania.
Keep responses under 3 sentences. Only answer questions about network security and scan results.
If asked about anything unrelated, redirect the user to scanning.
Detect the user language: if they write in Swahili, respond in Swahili. Otherwise English.\
"""

_INTENT_SYSTEM = """\
Extract the scan target from this request. Return ONLY valid JSON:
{"target": "<ip or hostname or null>", "level": <1|2|3>, "focus": "<or null>"}\
"""


def build_context(scan_history: list[dict]) -> str:
    """Format last 3 session scans as text context for the LLM."""
    if not scan_history:
        return "No scans performed in this session yet."
    lines = ["Recent scans this session:"]
    for s in scan_history[-3:]:
        cves = ", ".join(s.get("top_cves", [])[:3]) or "none"
        lines.append(
            f"  · {s['target']} — Grade {s['grade']} ({s['score']}/100)"
            f"  top CVEs: {cves}"
        )
    return "\n".join(lines)


async def dispatch(app: "AIVASApp", text: str, api_key: str | None) -> None:
    """Route free text: no-key info, scan intent, or Q&A about results."""
    if not api_key:
        app.tui_print(
            "[dim]No API key configured. AIVAS works fully without AI —[/dim]\n"
            "  [bold]/scan <target>[/bold]       direct scan\n"
            "  [bold]/config set api_key[/bold]  enable AI features\n"
            "  [bold]/doctor[/bold]              check setup"
        )
        return

    # Try to extract scan intent first (fast, cheap)
    try:
        intent = await _parse_intent(text, api_key)
    except Exception:
        intent = None

    if intent and intent.get("target"):
        from .scan import run_scan_pipeline
        app.tui_print(
            f"[dim]Understood: scan [bold]{intent['target']}[/bold]"
            + (f" at level {intent['level']}" if intent.get("level", 2) != 2 else "")
            + "[/dim]"
        )
        await run_scan_pipeline(app, intent["target"], intent.get("level", 2))
        return

    # No scan intent — answer as security assistant
    context = build_context(getattr(app, "_scan_history", []))
    prompt = f"{context}\n\nUser: {text}"
    try:
        response = await asyncio.to_thread(_call_groq, api_key, prompt)
        app.tui_print(f"[dim]AIVAS:[/dim] {response}")
    except Exception as exc:
        app.tui_print(f"[#e53935]AI error:[/#e53935] {exc}")


async def narrate_findings(app: "AIVASApp", findings: list[dict],
                            api_key: str, lang: str = "en") -> None:
    """Call narrator.narrate() on top 5 findings, display in output pane."""
    from aivas.narrator.narrator import narrate
    from aivas.narrator.providers import GroqProvider
    from aivas.formatting import print_narrations

    app.tui_print("[dim]Generating AI narration (top 5 findings)...[/dim]")
    top5 = findings[:5]
    try:
        prov = GroqProvider(api_key=api_key)
        enriched = await asyncio.to_thread(narrate, top5, prov)
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        c = Console(file=buf, highlight=False)
        print_narrations(enriched, lang=lang, console=c)
        app.tui_print(buf.getvalue())
    except Exception as exc:
        app.tui_print(f"[#e53935]Narration failed:[/#e53935] {exc}")


def _call_groq(api_key: str, user_msg: str) -> str:
    from groq import Groq
    client = Groq(api_key=api_key)
    resp = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=150,
    )
    return resp.choices[0].message.content.strip()


async def _parse_intent(text: str, api_key: str) -> dict:
    from aivas.narrator.intent import parse_intent
    from aivas.narrator.providers import GroqProvider
    prov = GroqProvider(api_key=api_key)
    return await asyncio.to_thread(parse_intent, text, prov)


def compute_score_summary(findings: list[dict]) -> dict:
    """Thin wrapper used by scan.py to avoid importing scorer directly."""
    from aivas.scorer import score_findings
    return score_findings(findings)
```

- [ ] **Step 4: Update `app.py` `_route` to use `ai.dispatch`**

```python
async def _route(self, text: str) -> None:
    if text.startswith("/"):
        from . import commands as _cmds
        await _cmds.handle(self, text)
    else:
        from .ai import dispatch
        from aivas import config as _cfg
        cfg = _cfg.load()
        api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
        await dispatch(self, text, api_key=api_key)
```

Add `import os` at top of `app.py`.

- [ ] **Step 5: Add `_scan_history` to `app.py` `__init__` and update in scan.py after save**

In `app.py`:
```python
self._scan_history: list[dict] = []
```

In `scan.py`, after `save_scan(...)`:
```python
    # Add to session context for AI
    from aivas.scorer import score_findings
    s2 = score_findings(findings)
    app._scan_history.append({
        "target": target,
        "score": s2["score"],
        "grade": s2["grade"],
        "top_cves": [f["cve_id"] for f in findings[:3]],
    })
    if len(app._scan_history) > 3:
        app._scan_history = app._scan_history[-3:]
```

- [ ] **Step 6: Wire narration into `_handle_scan_result_choice` in `app.py`**

```python
async def _handle_scan_result_choice(self, choice: str) -> None:
    from aivas.formatting import cve_table, misconfig_table
    from aivas import config as _cfg
    import os
    if choice == "report":
        if self._last_findings:
            self.tui_print(cve_table("Vulnerability Findings", self._last_findings))
        if self._last_misconfigs:
            self.tui_print(misconfig_table("Configuration Issues", self._last_misconfigs))
    elif choice == "narrate":
        cfg = _cfg.load()
        api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
        if not api_key:
            self.tui_print("[dim]No API key — set one with /config set api_key ...[/dim]")
            return
        lang = cfg.get("lang", "en")
        from .ai import narrate_findings
        await narrate_findings(self, self._last_findings[:5], api_key, lang=lang)
```

- [ ] **Step 7: Remove `/ask` and `/kev` from `commands.py` REGISTRY**

```python
REGISTRY: dict[str, tuple[str, str]] = {
    "scan":    ("/scan <target> [--level 1-3] [--udp]", "Full CVE scan"),
    "quick":   ("/quick <target>",                       "Quick scan (level 1)"),
    "deep":    ("/deep <target>",                        "Deep scan with UDP"),
    "doctor":  ("/doctor",                               "Check dependencies"),
    "history": ("/history [list|show <id>]",             "View past scans"),
    "config":  ("/config [set <key> <val>|show]",        "Manage configuration"),
    "clear":   ("/clear",                                "Clear output pane"),
    "copy":    ("/copy",                                 "Copy last scan to clipboard"),
    "exit":    ("/exit",                                 "Quit AIVAS"),
    "help":    ("/help [command]",                       "List commands or usage"),
}
```

Also remove `_cmd_ask` function and `"ask": _cmd_ask` from `_HANDLERS`.

- [ ] **Step 8: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_ai_dispatch_no_key_shows_helpful_message tests/test_tui_checklist.py::test_ai_session_context_includes_last_scan -v
```
Expected: PASS

- [ ] **Step 9: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/ai.py aivas/tui/app.py aivas/tui/commands.py
git commit -m "feat: AI wiring — free text dispatch, Groq narration, 3-scan session context"
```

---

## Task 11: KEV auto-sync on startup

**Files:**
- Modify: `aivas/tui/app.py` (`on_mount`)
- Modify: `aivas/tui/commands.py` (remove `_cmd_kev` from REGISTRY and handlers)

- [ ] **Step 1: Write the failing test**

```python
def test_kev_autosync_skips_when_recent():
    """KEV sync must be skipped if synced within 7 days."""
    from aivas.tui.app import _kev_needs_sync
    import sqlite3
    from aivas.database.schema import init_db
    from datetime import datetime, timezone, timedelta
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    # Mark as synced 3 days ago
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)",
        ("kev_last_updated", recent),
    )
    conn.commit()
    assert _kev_needs_sync(conn) is False

def test_kev_autosync_needed_when_old():
    """KEV sync must be needed if never synced or synced >7 days ago."""
    from aivas.tui.app import _kev_needs_sync
    import sqlite3
    from aivas.database.schema import init_db
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    assert _kev_needs_sync(conn) is True   # never synced
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_kev_autosync_skips_when_recent tests/test_tui_checklist.py::test_kev_autosync_needed_when_old -v
```

- [ ] **Step 3: Add `_kev_needs_sync` to `app.py` (module level)**

```python
def _kev_needs_sync(conn: "sqlite3.Connection") -> bool:
    """Return True if KEV has never been synced or was synced >7 days ago."""
    from datetime import datetime, timezone, timedelta
    row = conn.execute(
        "SELECT value FROM sync_meta WHERE key = 'kev_last_updated'"
    ).fetchone()
    if not row:
        return True
    try:
        last = datetime.fromisoformat(row["value"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last) > timedelta(days=7)
    except ValueError:
        return True
```

- [ ] **Step 4: Add KEV auto-sync to `on_mount` in `app.py`**

```python
async def on_mount(self) -> None:
    log = self.query_one("#output", RichLog)
    log.write(_BANNER)
    self.query_one("#cmd-input", Input).focus()

    # KEV auto-sync (background, non-blocking)
    if _kev_needs_sync(self.conn):
        self.run_worker(self._sync_kev_background(), exclusive=False)

    # First-run wizard
    from aivas import config as _config
    cfg = _config.load()
    if not cfg.get("api_key"):
        from .screens import SetupWizardScreen
        result = await self.push_screen_wait(SetupWizardScreen())
        if result:
            self.tui_print(
                f"[dim]Setup saved. Provider: {result['provider']}.[/dim]"
            )

async def _sync_kev_background(self) -> None:
    """Download and apply KEV feed in the background at startup."""
    from aivas.database.kev import fetch_kev, mark_kev
    from datetime import datetime, timezone
    try:
        cve_ids = await asyncio.to_thread(fetch_kev)
        count = mark_kev(self.conn, cve_ids)
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)",
            ("kev_last_updated", now),
        )
        self.conn.commit()
        self.tui_print(
            f"[dim]KEV: {count:,} active exploits tracked  "
            f"(synced {datetime.now().strftime('%Y-%m-%d')})[/dim]"
        )
    except Exception:
        # Silently skip if offline — no crash, no noise
        pass
```

- [ ] **Step 5: Run tests**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/test_tui_checklist.py::test_kev_autosync_skips_when_recent tests/test_tui_checklist.py::test_kev_autosync_needed_when_old -v
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/app.py
git commit -m "feat: KEV auto-sync on startup (background, silent on failure), remove /kev command"
```

---

## Task 12: Checklist cleanup + full test run

**Files:**
- Modify: `tests/test_tui_checklist.py` (remove obsolete tests, add new ones)
- Modify: `docs/test-results/tui-checklist.md` (clean for Round 5)

- [ ] **Step 1: Run full test suite**

```bash
cd /home/cyberpunk/aivas && /home/cyberpunk/.local/bin/pytest tests/ -v --tb=short 2>&1 | tee /tmp/sprint4_test_run.txt
```
Expected: all PASS. Fix any failures before proceeding.

- [ ] **Step 2: Update checklist document**

Rewrite `docs/test-results/tui-checklist.md`:
- Remove all "→ fixed R3" annotations
- Update version to `v0.2.0`
- Mark all automated items as AUTO-TESTED
- Clear all manual test results (blank) so user can test fresh
- Add new items: KEV auto-sync status, post-scan screen, first-run wizard, AI narration
- Move all PASS items verified by automated tests to a "Verified by CI" section
- Keep only genuine manual-only items in the test table

- [ ] **Step 3: Commit**

```bash
cd /home/cyberpunk/aivas
git add tests/ docs/test-results/tui-checklist.md
git commit -m "test: update checklist for Sprint 4, full suite passing"
```

---

## Verification Checklist (self-review)

**Spec coverage check:**
- [x] Color palette — Task 1
- [x] TAB crash fix — Task 2
- [x] Autocomplete with descriptions — Task 2
- [x] HS3 markup crash — Task 3
- [x] save_scan bug — Task 3
- [x] SC7 sudo fix — Task 4
- [x] ESC cancel subprocess — Task 5
- [x] Input lock during scan — Task 5
- [x] Flag whitelist — Task 6
- [x] commands.py ≤200 lines — Task 6
- [x] Input bar two Rules — Task 7
- [x] Step-line progress — Task 8
- [x] Post-scan ScanResultScreen — Task 9
- [x] First-run SetupWizardScreen — Task 9
- [x] Free text AI dispatch — Task 10
- [x] Groq narration wiring — Task 10
- [x] Session context (3 scans) — Task 10
- [x] Remove /ask, /kev from registry — Tasks 10, 11
- [x] KEV auto-sync startup — Task 11
- [x] Checklist updated — Task 12
- [x] Table expand=True for CVE/misconfig — Task 1 (formatting.py)
- [x] GRADE_COLOR single color on score line — Task 1 (colors.py)
- [x] Ctrl+Q for quit — Task 7 (app.py BINDINGS update)

**Missing item found during review — add to Task 7:**
Change `Binding("ctrl+c", "quit", ...)` → `Binding("ctrl+q", "quit", "Quit", priority=True)` in `app.py` BINDINGS. This frees Ctrl+C for terminal copy.
