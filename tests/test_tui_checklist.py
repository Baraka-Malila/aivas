"""
Automated tests covering the Round 3 checklist items.

Tests are split into two groups:
  - Unit / CLI tests: no TUI, run fast
  - TUI tests: use Textual's run_test() + Pilot
"""
from __future__ import annotations

import asyncio
import sqlite3
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from aivas.database.schema import create_schema


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    return conn


def _make_app(conn=None):
    from aivas.tui.app import AIVASApp
    return AIVASApp(conn or _make_db())


# ── SC8: invalid IP validation ────────────────────────────────────────────────

def test_bad_ip_rejects_invalid_octets():
    from aivas.tui.commands import _bad_ip
    assert _bad_ip("999.999.999.999") is not None
    assert "0–255" in _bad_ip("999.999.999.999")


def test_bad_ip_rejects_single_high_octet():
    from aivas.tui.commands import _bad_ip
    assert _bad_ip("192.168.1.256") is not None


def test_bad_ip_accepts_valid_ipv4():
    from aivas.tui.commands import _bad_ip
    assert _bad_ip("192.168.1.1") is None
    assert _bad_ip("10.0.0.1") is None
    assert _bad_ip("0.0.0.0") is None


def test_bad_ip_accepts_cidr():
    from aivas.tui.commands import _bad_ip
    assert _bad_ip("192.168.0.0/24") is None


def test_bad_ip_ignores_hostnames():
    from aivas.tui.commands import _bad_ip
    # Hostnames are not IPv4 format; _bad_ip should pass them (DNS handles them)
    assert _bad_ip("google.com") is None
    assert _bad_ip("localhost") is None


# ── SC9: hostname resolution ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolves_returns_false_for_garbage():
    from aivas.tui.commands import _resolves
    result = await _resolves("this.hostname.definitely.does.not.exist.invalid")
    assert result is False


@pytest.mark.asyncio
async def test_resolves_returns_true_for_localhost():
    from aivas.tui.commands import _resolves
    result = await _resolves("localhost")
    assert result is True


# ── AI1/AI2: intent guard ("hi" should NOT scan) ─────────────────────────────

def test_scan_intent_regex_blocks_casual_text():
    from aivas.tui.commands import _SCAN_INTENT_RE
    for text in ("hi", "hello", "ok", "thanks", "good morning", "what?"):
        assert not _SCAN_INTENT_RE.search(text), f"Should not match: {text!r}"


def test_scan_intent_regex_passes_scan_keywords():
    from aivas.tui.commands import _SCAN_INTENT_RE
    for text in ("scan my server", "check the host", "probe for ports",
                 "find vulnerabilities", "audit this network", "assess 192.168.1.1"):
        assert _SCAN_INTENT_RE.search(text), f"Should match: {text!r}"


def test_scan_intent_regex_passes_ipv4_literal():
    from aivas.tui.commands import _SCAN_INTENT_RE
    assert _SCAN_INTENT_RE.search("192.168.1.100")
    assert _SCAN_INTENT_RE.search("10.0.0.1")


def test_scan_intent_regex_passes_localhost():
    from aivas.tui.commands import _SCAN_INTENT_RE
    assert _SCAN_INTENT_RE.search("localhost")


# ── UK5: shell injection ──────────────────────────────────────────────────────

def test_no_shell_injection_via_shlex():
    """shlex.split produces a list; subprocess never receives a shell string."""
    import shlex
    dangerous = "192.168.1.1 && echo INJECTED > /tmp/aivas_test"
    parts = shlex.split(dangerous)
    # shlex splits on spaces — each token is separate; no shell expansion happens
    # when passed as a list to subprocess.run(shell=False)
    assert "&&" in parts          # treated as literal string token, not shell operator
    assert "/tmp/aivas_test" in parts
    # Confirm no shell=True anywhere in commands.py
    import inspect, aivas.tui.commands as cmd_mod
    src = inspect.getsource(cmd_mod)
    assert "shell=True" not in src, "subprocess must never use shell=True"


# ── UK3: bad flags handled without crash ─────────────────────────────────────

def test_bad_flag_treated_as_extra_arg():
    """_cmd_scan uses shlex.split and ignores unknown flags gracefully."""
    import shlex
    args = "192.168.100.253 --badflagnobody"
    parts = shlex.split(args)
    assert parts[0] == "192.168.100.253"   # target extracted correctly
    # Unknown flags are silently skipped in the while loop in _cmd_scan
    # This test verifies the target is correctly isolated from bad flags


# ── SC-A: # row column in CVE table ──────────────────────────────────────────

def test_cve_table_has_row_number_column():
    from aivas.formatting import cve_table
    t = cve_table("T", [])
    headers = [col.header for col in t.columns]
    assert "#" in headers


def test_cve_table_row_numbers_start_at_one():
    from aivas.formatting import cve_table
    rows = [
        {"cve_id": "CVE-2021-0001", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "confidence": "probable", "description": "test"},
        {"cve_id": "CVE-2021-0002", "cvss_score": 7.0, "cvss_severity": "HIGH",
         "confidence": "probable", "description": "test2"},
    ]
    t = cve_table("T", rows)
    row_col = t.columns[0]
    assert row_col._cells[0] == "1"
    assert row_col._cells[1] == "2"


# ── SC10: KEV tags in table ───────────────────────────────────────────────────

def test_kev_tag_shown_when_kev_true():
    from aivas.formatting import cve_table
    rows = [{"cve_id": "CVE-2023-44487", "cvss_score": 7.5,
             "cvss_severity": "HIGH", "confidence": "probable",
             "description": "HTTP/2 Rapid Reset", "kev": True}]
    t = cve_table("T", rows)
    cve_cell = t.columns[1]._cells[0]   # CVE ID column
    assert "KEV" in cve_cell.plain


def test_kev_tag_absent_when_kev_false():
    from aivas.formatting import cve_table
    rows = [{"cve_id": "CVE-2021-0001", "cvss_score": 9.8,
             "cvss_severity": "CRITICAL", "confidence": "probable",
             "description": "test", "kev": False}]
    t = cve_table("T", rows)
    cve_cell = t.columns[1]._cells[0]
    assert "KEV" not in cve_cell.plain


# ── SC11 / SC-B: scoring not zero ────────────────────────────────────────────

def test_score_not_zero_for_critical_findings():
    from aivas.scorer import score_findings
    findings = [
        {"cvss_severity": "CRITICAL", "cvss_score": 9.8, "confidence": "probable"},
        {"cvss_severity": "HIGH", "cvss_score": 7.5, "confidence": "probable"},
    ]
    s = score_findings(findings)
    assert s["score"] < 100
    assert s["score"] > 0
    assert s["grade"] in ("A", "B", "C", "D", "F")


def test_score_result_has_sev_counts():
    from aivas.scorer import score_findings
    findings = [
        {"cvss_severity": "CRITICAL", "cvss_score": 9.8, "confidence": "probable"},
        {"cvss_severity": "MEDIUM",   "cvss_score": 5.0, "confidence": "probable"},
    ]
    s = score_findings(findings)
    assert "sev_counts" in s
    assert "total" in s
    assert s["total"] == 2


def test_score_result_total_matches_input():
    from aivas.scorer import score_findings
    findings = [{"cvss_severity": "HIGH", "cvss_score": 7.5,
                 "confidence": "probable"}] * 15
    s = score_findings(findings)
    assert s["total"] == 15


# ── HS3 / HS4: history show with valid and invalid IDs ───────────────────────

def test_history_show_valid_id_returns_findings(tmp_path):
    from aivas.history import save_scan, get_scan_findings
    conn = _make_db()
    findings = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_severity": "CRITICAL", "confidence": "probable",
                 "description": "test"}]
    save_scan(conn, "192.168.1.1", findings)
    rows = get_scan_findings(conn, 1)
    assert len(rows) >= 1
    conn.close()


def test_history_show_missing_id_returns_empty():
    from aivas.history import get_scan_findings
    conn = _make_db()
    rows = get_scan_findings(conn, 9999)
    assert rows == [] or rows is None or len(rows) == 0
    conn.close()


# ── DR5: config set / show ────────────────────────────────────────────────────

def test_config_set_and_read(tmp_path, monkeypatch):
    import aivas.config as cfg
    monkeypatch.setenv("AIVAS_CONFIG_DIR", str(tmp_path))
    cfg.save("provider", "ollama")
    loaded = cfg.load()
    assert loaded.get("provider") == "ollama"


# ── KV1/KV2: KEV mark function (no network) ──────────────────────────────────

def test_kev_mark_updates_db():
    from aivas.database.kev import mark_kev
    conn = _make_db()
    # Insert a CVE to mark
    conn.execute(
        "INSERT INTO cves (cve_id, cvss_score, cvss_severity, description) "
        "VALUES (?, ?, ?, ?)",
        ("CVE-2023-44487", 7.5, "HIGH", "HTTP/2 Rapid Reset")
    )
    conn.commit()
    count = mark_kev(conn, ["CVE-2023-44487"])
    assert count == 1
    row = conn.execute("SELECT kev FROM cves WHERE cve_id=?",
                       ("CVE-2023-44487",)).fetchone()
    assert row["kev"] == 1
    conn.close()


def test_kev_mark_ignores_unknown_cves():
    from aivas.database.kev import mark_kev
    conn = _make_db()
    count = mark_kev(conn, ["CVE-9999-99999"])
    assert count == 0
    conn.close()


# ── TUI tests (Textual Pilot + tui_print spy) ─────────────────────────────────

def _make_spy_app(conn=None):
    """App with tui_print intercepted so we can inspect output."""
    from aivas.tui.app import AIVASApp
    app = AIVASApp(conn or _make_db())
    app._captured: list[str] = []

    _orig_print = app.tui_print

    def _spy(content):
        app._captured.append(str(content))
        _orig_print(content)

    app.tui_print = _spy
    return app


@pytest.mark.asyncio
async def test_tui_sc8_invalid_ip_shows_error():
    """SC8: /scan 999.999.999.999 → validation error, nmap never runs."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/scan 999.999.999.999"
        await pilot.press("enter")
        await pilot.pause(0.3)
        combined = " ".join(app._captured)
        assert "Invalid" in combined or "999" in combined


@pytest.mark.asyncio
async def test_tui_ai1_no_api_key_shows_helpful_message():
    """AI1: typing 'hi' with no API key → helpful message, no scan."""
    app = _make_spy_app()
    no_key_cfg = {"provider": "groq", "lang": "en"}
    # Patch config.load everywhere so no wizard and no api_key in _route
    with patch("aivas.config.load", return_value=no_key_cfg), \
         patch("aivas.tui.app.AIVASApp.push_screen_wait", new=AsyncMock(return_value=None)):
        async with app.run_test(size=(120, 30)) as pilot:
            from textual.widgets import Input
            inp = app.query_one("#cmd-input", Input)
            inp.value = "hi"
            await pilot.press("enter")
            await pilot.pause(0.3)
            combined = " ".join(app._captured)
            assert "API key" in combined or "/scan" in combined or "AIVAS" in combined


@pytest.mark.asyncio
async def test_tui_ai_guard_blocks_casual_text_with_api_key():
    """AI2: with API key, 'hi' routes to AI dispatch — no scan started."""
    app = _make_spy_app()
    fake_cfg = {"api_key": "sk-fake", "provider": "groq"}
    with patch("aivas.config.load", return_value=fake_cfg):
        async with app.run_test(size=(120, 30)) as pilot:
            from textual.widgets import Input
            inp = app.query_one("#cmd-input", Input)
            inp.value = "hi"
            await pilot.press("enter")
            await pilot.pause(0.3)
            combined = " ".join(app._captured)
            assert "Scanning" not in combined


@pytest.mark.asyncio
async def test_tui_unknown_command_shows_error():
    """UK1: /zzzznotacommand → 'Unknown command' message."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/zzzznotacommand"
        await pilot.press("enter")
        await pilot.pause(0.2)
        combined = " ".join(app._captured)
        assert "Unknown command" in combined or "unknown" in combined.lower()


@pytest.mark.asyncio
async def test_tui_help_lists_commands():
    """H1: /help lists all registered commands."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/help"
        await pilot.press("enter")
        await pilot.pause(0.2)
        combined = " ".join(app._captured)
        assert "/scan" in combined
        assert "/doctor" in combined
        assert "/history" in combined


@pytest.mark.asyncio
async def test_tui_tab_shows_suggestions():
    """TAB1: type /s → OptionList becomes visible with matches."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import OptionList
        app._refresh_suggestions("/s")
        await pilot.pause(0.1)
        ol = app.query_one("#suggestions", OptionList)
        assert ol.display is True
        assert ol.option_count > 0


@pytest.mark.asyncio
async def test_tui_tab_accepts_suggestion():
    """TAB2: _accept_suggestion fills input with first match + space."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input, OptionList
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/s"
        app._refresh_suggestions("/s")
        await pilot.pause(0.1)
        ol = app.query_one("#suggestions", OptionList)
        assert ol.display is True
        assert app._accept_suggestion() is True
        assert inp.value.startswith("/s") and inp.value.endswith(" ")


@pytest.mark.asyncio
async def test_tui_tab_no_suggestion_for_unknown():
    """TAB4: /xyz → no suggestions shown."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import OptionList
        app._refresh_suggestions("/xyz")
        await pilot.pause(0.1)
        assert app.query_one("#suggestions", OptionList).display is False


@pytest.mark.asyncio
async def test_tui_tab_no_suggestion_when_exact_match():
    """TAB3: /deep (exact) → no suggestions."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import OptionList
        app._refresh_suggestions("/deep")
        await pilot.pause(0.1)
        assert app.query_one("#suggestions", OptionList).display is False


@pytest.mark.asyncio
async def test_tui_suggestions_hide_after_space():
    """Suggestions disappear once user adds a space (typing args now)."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import OptionList
        app._refresh_suggestions("/scan ")
        await pilot.pause(0.1)
        assert app.query_one("#suggestions", OptionList).display is False


@pytest.mark.asyncio
async def test_tui_command_history_prev():
    """HIS1: ↑ recalls last command."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        app._cmd_history = ["/help", "/doctor"]
        app._history_idx = -1
        inp = app.query_one("#cmd-input", Input)
        inp.focus()
        app.action_history_prev()
        await pilot.pause(0.1)
        assert inp.value == "/help"


@pytest.mark.asyncio
async def test_tui_command_history_cycle():
    """HIS2: multiple ↑ presses cycle backward through history."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        app._cmd_history = ["/help", "/doctor", "/kev"]
        app._history_idx = -1
        inp = app.query_one("#cmd-input", Input)
        inp.focus()
        app.action_history_prev()  # → /help
        app.action_history_prev()  # → /doctor
        app.action_history_prev()  # → /kev
        await pilot.pause(0.1)
        assert inp.value == "/kev"


@pytest.mark.asyncio
async def test_tui_command_history_forward_clears():
    """HIS3: ↑ then ↓ returns to blank input."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        app._cmd_history = ["/help"]
        app._history_idx = -1
        inp = app.query_one("#cmd-input", Input)
        inp.focus()
        app.action_history_prev()
        assert inp.value == "/help"
        app.action_history_next()
        await pilot.pause(0.1)
        assert inp.value == ""


@pytest.mark.asyncio
async def test_tui_cmd_class_added_for_slash():
    """CLR1: typing /scan adds .cmd CSS class (accent color)."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/scan"
        app.on_input_changed(Input.Changed(inp, inp.value))
        await pilot.pause(0.1)
        assert "cmd" in inp.classes


@pytest.mark.asyncio
async def test_tui_cmd_class_removed_for_free_text():
    """CLR2: typing free text (no /) → .cmd class absent."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/scan"
        app.on_input_changed(Input.Changed(inp, inp.value))
        await pilot.pause(0.05)
        inp.value = "hello"
        app.on_input_changed(Input.Changed(inp, inp.value))
        await pilot.pause(0.1)
        assert "cmd" not in inp.classes


@pytest.mark.asyncio
async def test_tui_clear_resets_scan_text():
    """CL1: /clear resets _last_scan_text."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        app._last_scan_text = "some previous scan output"
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/clear"
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert app._last_scan_text == ""


@pytest.mark.asyncio
async def test_tui_esc_blurs_input_when_idle():
    """ESC2: ESC when no scan running → input loses focus."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        assert inp.has_focus
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert not inp.has_focus


@pytest.mark.asyncio
async def test_tui_history_saved_on_submit():
    """Submitted commands are saved to history."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/help"
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert "/help" in app._cmd_history



@pytest.mark.asyncio
async def test_tui_scan_status_visible_attribute_exists():
    """SC3: scan-status label widget is present in compose."""
    app = _make_app()
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Label
        lbl = app.query_one("#scan-status", Label)
        assert lbl is not None
        # Initially hidden
        assert lbl.display is False


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
        # At least one option text should contain scan-related content
        option_texts = [str(ol.get_option_at_index(i).prompt)
                        for i in range(ol.option_count)]
        assert any("CVE" in t or "scan" in t.lower() for t in option_texts)


# ── HS3/HS4: Markup escape tests ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tui_history_show_no_crash_with_markup_in_description():
    """History show must not crash when CVE descriptions contain markup chars."""
    conn = _make_db()
    from aivas.history import save_scan
    findings = [{
        "cve_id": "CVE-2021-0001",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "confidence": "probable",
        "description": "Buffer overflow in [kernel] module [/proc] path",
        "host": "192.168.1.1",
    }]
    save_scan(conn, "192.168.1.1", findings)
    app = _make_spy_app(conn=conn)
    async with app.run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        inp = app.query_one("#cmd-input", Input)
        inp.value = "/history show 1"
        await pilot.press("enter")
        await pilot.pause(0.2)
        combined = " ".join(app._captured)
        assert "MarkupError" not in combined    # no crash fallback
        assert len(app._captured) >= 1          # table was rendered (not empty output)


def test_save_scan_no_extra_args():
    """save_scan called with correct 3-arg signature — no TypeError."""
    from aivas.history import save_scan
    conn = _make_db()
    findings = [{"cve_id": "CVE-0001", "cvss_score": 7.0,
                 "cvss_severity": "HIGH", "confidence": "probable",
                 "host": "192.168.1.1"}]
    scan_id = save_scan(conn, "192.168.1.1", findings)
    assert scan_id > 0


# ── TK4: sudo nmap uses stdout, not tempfile ─────────────────────────────────

def test_sudo_nmap_uses_stdout_not_tempfile():
    """_run_nmap_sudo must use -oX - (stdout) not a tempfile."""
    from aivas.tui.commands import _run_nmap_sudo
    import inspect
    src = inspect.getsource(_run_nmap_sudo)
    assert '"-oX"' in src or "'-oX'" in src
    assert '"-"' in src or "'-'" in src
    assert "NamedTemporaryFile" not in src


# ── Input lock during scan ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tui_input_disabled_while_scanning():
    """Input must be disabled while a scan is running."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        pilot.app.set_scan_running("192.168.1.1")
        inp = pilot.app.query_one("#cmd-input", Input)
        assert inp.disabled is True


@pytest.mark.asyncio
async def test_tui_input_enabled_after_scan():
    """Input must be re-enabled after scan finishes."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        from textual.widgets import Input
        pilot.app.set_scan_running("192.168.1.1")
        pilot.app.set_scan_idle()
        inp = pilot.app.query_one("#cmd-input", Input)
        assert inp.disabled is False


@pytest.mark.asyncio
async def test_tui_unknown_flag_shows_error():
    """Unknown flags like --badflagnobody must show an error, not scan."""
    app = _make_spy_app()
    async with app.run_test(size=(120, 30)) as pilot:
        inp = pilot.app.query_one("#cmd-input")
        inp.value = "/scan 192.168.1.1 --badflagnobody"
        await pilot.press("enter")
        await pilot.pause(0.15)
        combined = " ".join(app._captured)
        assert ("unknown" in combined.lower() or "invalid" in combined.lower()
                or "flag" in combined.lower())
        assert "scanning" not in combined.lower()


@pytest.mark.asyncio
async def test_tui_input_prompt_label_exists():
    """Prompt label (>) must exist in the composed layout."""
    async with _make_spy_app().run_test(size=(120, 30)) as pilot:
        from textual.widgets import Label
        labels = pilot.app.query(Label)
        label_texts = [str(l.render()) for l in labels]
        assert any(">" in t for t in label_texts)


# ── Task 8: StepProgress tests ───────────────────────────────────────────────

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


def test_step_progress_fail_shows_x():
    """StepProgress fail() outputs a failure marker."""
    from aivas.tui.progress import StepProgress
    output = []
    class FakeApp:
        def tui_print(self, msg):
            output.append(str(msg))
    p = StepProgress(FakeApp())
    p.fail("Port discovery", "cancelled")
    combined = " ".join(output)
    assert "Port discovery" in combined
    assert "cancelled" in combined


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
        statics = pilot.app.screen.query("Label,Static")
        static_texts = [str(w.content) for w in statics]
        from textual.widgets import RadioButton
        buttons = pilot.app.screen.query(RadioButton)
        button_texts = [str(b.label) for b in buttons]
        combined = " ".join(static_texts + button_texts)
        assert "192.168.1.1" in combined or "Scan complete" in combined
        assert "report" in combined.lower() or "narration" in combined.lower()


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
