# AIVAS TUI — Manual Test Checklist

**Instructions:** Write `PASS`, `FAIL`, or a short note in the Result column. Leave blank if not tested yet.

**Version under test:** v0.1.0
**Tester:** Baraka Malila
**Date:**

---

## Before Testing — Required Steps

```bash
# 1. Ensure nmap is installed
which nmap

# 2. Ensure CVE database is populated
aivas search apache   # should return results

# 3. Launch TUI
export PATH="$HOME/.local/bin:$PATH"
aivas
```

---

## Round 3 — Quick Reference (all tests needing attention)

Sprint 3 fixes applied. Items marked "→ fixed R3" had their root cause resolved this sprint.
All Round 1 PASSes are still valid unless you want to spot-check.

| # | Area | What to test | Result | Command to run |
|---|------|-------------|--------|---------------|
| SC3 | /scan | Progress label visible during scan (amber bar + "Scanning…") | FAIL-no progress at all, too many colors on the output, also the appearing kind of circular loader on the bottom is a static one..even if it worked its not better-we must redesign here-i have a suggestion and exact reference for this loader. | `/scan 192.168.100.253` — watch status bar below output |
| SC7 | /scan | UDP scan pauses TUI, shows sudo prompt, resumes after | FAIL → it does pause but fails with this error: [AIVAS] UDP scan requires root. Enter your sudo password below.
(Tip: run once to avoid this: sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap)

[sudo] password for cyberpunk: 
Failed to open XML output file /tmp/tmp6p8a0wso.xml for writing
QUITTING! | `/scan 192.168.100.253 --udp` |
| SC8 | /scan | Invalid IP → clear error, not "no services found" | PASS | `/scan 999.999.999.999` |
| SC9 | /scan | Non-existent hostname → DNS error, not "no services found" | PASS | `/scan thishostnamedoesnotexist` |
| SC10 | /scan | [KEV] tag visible in CVE table | FAIL → with an error: /kev                                                                                                                                                                                                         ┃
┃  Downloading CISA KEV feed...                                                                                                                                                                                   ┃
┃  KEV sync failed: <urlopen error [Errno -3] Temporary failure in name resolution>  ; also am not sure we need this command /kev shouldn't this just be auto..without overcomplicating things..if there are kevs they should be shown always! | Run `/kev` first, then `/scan 192.168.100.253` |
| SC11 | /scan | Score is not 0/F — shows meaningful grade | PASS → But am not sure of it the output was this "Risk Score: 33/100  Grade F  — 30 findings (19 critical, 11 high)" | `/scan 192.168.100.253` |
| SC-A | /scan | CVE table has `#` row number column (1, 2, 3…) | PASS | `/scan 192.168.100.253` |
| SC-B | /scan | Score line shows count breakdown e.g. "30 findings (14 critical…)" | PASS | `/scan 192.168.100.253` |
| SC-C | /scan | Scan auto-saves; `/history list` shows it after | PASS-But i need you to confirm if its really saving the latest ones and whats best since we are introducing reports?| Run scan, then `/history list` |
| SC-D | /scan | Second `/scan` while first runs shows "already running" | FAIL-i see the input does not take any inpuut while a process is going on so in that case this might be a best design too for now or not?..should i mark it pass? though tis buggy too since it takes the input sliently and whows them when the scan is done at the input section! | Start `/scan 192.168.100.253 --level 3`, immediately type `/scan 192.168.100.253` |
| QD3 | /deep | `/deep <target>` uses UDP without `--udp` flag | FAIL → Since the sudo apssword confirmation failed even with right credentials same error as on top but on TUI we have ; /deep 127.0.0.1                                                                                                                                                                                              ┃
┃  Scanning 127.0.0.1  (level 2, UDP)                                                                                                                                                                             ┃
┃  Scan error: nmap exited 1 (sudo password wrong or denied?) | `/deep 192.168.100.253` |
| HS3 | /history | `/history show 1` — no crash | FAIL-you can see the rror below along with the sudo error;

 % aivas

[AIVAS] UDP scan requires root. Enter your sudo password below.
(Tip: run once to avoid this: sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap)

[sudo] password for cyberpunk: 
Failed to open XML output file /tmp/tmpq4ebjymf.xml for writing
QUITTING!

[AIVAS] UDP scan requires root. Enter your sudo password below.
(Tip: run once to avoid this: sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap)

Failed to open XML output file /tmp/tmpxb_35mj5.xml for writing
QUITTING!
╭─────────────────────────────────────────────────────────────────────────────────────── Traceback (most recent call last) ───────────────────────────────────────────────────────────────────────────────────────╮
│ /home/cyberpunk/aivas/aivas/tui/app.py:124 in on_input_submitted                                                                                                                                                │
│                                                                                                                                                                                                                 │
│   121 │   │   except Exception as exc:                                                         ╭───────────────────────────────────────── locals ──────────────────────────────────────────╮                    │
│   122 │   │   │   self.set_scan_idle()                                                         │ event = Submitted()                                                                       │                    │
│   123 │   │   │   self._scan_task = None                                                       │   log = RichLog(id='output')                                                              │                    │
│ ❱ 124 │   │   │   log.write(                                                                   │  self = AIVASApp(title='AIVAS', classes={'-dark-mode'}, pseudo_classes={'focus', 'dark'}) │                    │
│   125 │   │   │   │   f"[bold red]Unexpected error:[/bold red] {type(exc).__name__}: {exc}\n"  │  text = '/history show 1'                                                                 │                    │
│   126 │   │   │   │   "[dim]This is a bug — please report it. The TUI is still running.[/dim]" ╰───────────────────────────────────────────────────────────────────────────────────────────╯                    │
│   127 │   │   │   )                                                                                                                                                                                             │
│                                                                                                                                                                                                                 │
│ /home/cyberpunk/.local/lib/python3.10/site-packages/textual/widgets/_rich_log.py:215 in write                                                                                                                   │
│                                                                                                                                                                                                                 │
│   212 │   │   │   )                                                                            ╭────────────────────────────────────────────── locals ──────────────────────────────────────────────╮           │
│   213 │   │   │   return self                                                                  │    animate = False                                                                                 │           │
│   214 │   │                                                                                    │    content = "[bold red]Unexpected error:[/bold red] MarkupError: closing tag '[/]' at positio"+95 │           │
│ ❱ 215 │   │   renderable = self._make_renderable(content)                                      │     expand = False                                                                                 │           │
│   216 │   │   auto_scroll = self.auto_scroll if scroll_end is None else scroll_end             │ scroll_end = None                                                                                  │           │
│   217 │   │                                                                                    │       self = RichLog(id='output')                                                                  │           │
│   218 │   │   console = self.app.console                                                       │     shrink = True                                                                                  │           │
│                                                                                                │      width = None                                                                                  │           │
│                                                                                                ╰────────────────────────────────────────────────────────────────────────────────────────────────────╯           │
│                                                                                                                                                                                                                 │
│ /home/cyberpunk/.local/lib/python3.10/site-packages/textual/widgets/_rich_log.py:162 in _make_renderable                                                                                                        │
│                                                                                                                                                                                                                 │
│   159 │   │   else:                                                                            ╭──────────────────────────────────────────── locals ─────────────────────────────────────────────╮              │
│   160 │   │   │   if isinstance(content, str):                                                 │ content = "[bold red]Unexpected error:[/bold red] MarkupError: closing tag '[/]' at positio"+95 │              │
│   161 │   │   │   │   if self.markup:                                                          │    self = RichLog(id='output')                                                                  │              │
│ ❱ 162 │   │   │   │   │   renderable = Text.from_markup(content)                               ╰─────────────────────────────────────────────────────────────────────────────────────────────────╯              │
│   163 │   │   │   │   else:                                                                                                                                                                                     │
│   164 │   │   │   │   │   renderable = Text(content)                                                                                                                                                            │
│   165 │   │   │   │   if self.highlight:                                                                                                                                                                        │
│                                                                                                                                                                                                                 │
│ /home/cyberpunk/.local/lib/python3.10/site-packages/rich/text.py:287 in from_markup                                                                                                                             │
│                                                                                                                                                                                                                 │
│ /home/cyberpunk/.local/lib/python3.10/site-packages/rich/markup.py:174 in render                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
MarkupError: closing tag '[/]' at position 65 has nothing to close

 | `/history show 1` |
| HS4 | /history | `/history show 9999` — "not found", no crash | PASS | `/history show 9999` |
| KV1 | /kev | `/kev` completes, no SQLite crash | FAIL → /kev                                                                                                                                                                                                         ┃
┃  Downloading CISA KEV feed...                                                                                                                                                                                   ┃
┃  KEV sync failed: <urlopen error [Errno -3] Temporary failure in name resolution> | `/kev` |
| KV2 | /kev | `/kev` shows CVE count | FAIL → same error above | `/kev` (watch for count line) |
| KV3 | /kev | `/kev` offline → error, no crash | FAIL  | Turn off wifi, run `/kev` |
| KV4 | /kev | `/kev` second run — no errors or duplicates | FAIL  | Run `/kev` twice |
| DR5 | /doctor | API key shows "configured" after setting | PASS | `/config set api_key sk-test123` then `/doctor` |
| ESC1 | Input | ESC during running scan cancels it | FAIL → ESC does nothing at all even when pressed mutliple times!! | Start `/scan 192.168.100.253 --level 3`, then press ESC |
| ESC2 | Input | ESC when idle blurs the input bar | PASS → But of what use is this! do we  need this? if not remove asap. | Press ESC with no scan running |
| TAB1 | Input | Type `/s` → dropdown shows `/scan`, `/show`… below input | PASS → But the ux is extremely poor i have added instructions and references on the bottom of this section so we can redesign this part and so its active.| Type `/s` (no Enter) |
| TAB2 | Input | Tab accepts the highlighted suggestion | PASS → but we might move to enter also since the current ui does not highlight any selected or move between the auto suggested commmands..we'll at redesign..but for now tab selects the first command then when tab is cliekd again it crashes the system with this error;
╭─────────────────────────────────────────────────────────────────────────────────────── Traceback (most recent call last) ───────────────────────────────────────────────────────────────────────────────────────╮
│ /home/cyberpunk/aivas/aivas/tui/input_actions.py:86 in action_accept_or_cycle                                                                                                                                   │
│                                                                                                                                                                                                                 │
│   83 │   │   inp = self.query_one("#cmd-input", Input)                                        ╭───────────────────────────────────────── locals ─────────────────────────────────────────╮                      │
│   84 │   │   if inp.has_focus and self._accept_suggestion():                                  │  inp = Input(id='cmd-input', classes='cmd -valid')                                       │                      │
│   85 │   │   │   return                                                                       │ self = AIVASApp(title='AIVAS', classes={'-dark-mode'}, pseudo_classes={'dark', 'focus'}) │                      │
│ ❱ 86 │   │   self.focus_next()                                                                ╰──────────────────────────────────────────────────────────────────────────────────────────╯                      │
│   87                                                                                                                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
AttributeError: 'AIVASApp' object has no attribute 'focus_next'
 | Type `/s`, press Tab |
| TAB3 | Input | Type `/deep` exactly → no suggestions shown | PASS | Type `/deep` (no space) |
| TAB4 | Input | Type `/xyz` → no suggestion, no crash | PASS | Type `/xyz` |
| HIS1 | Input | Up arrow recalls last command | PASS | Type `/help`, Enter, then press ↑ |
| HIS2 | Input | Up/down cycles through command history | PASS | Run 3 commands, then press ↑ multiple times |
| HIS3 | Input | Down arrow back to blank when at newest | PASS | Press ↑ to go back, then ↓ to return to empty |
| CLR1 | Input | `/` prefix turns input text accent color | PASS→Bu we are going to make changes on the colors i need suggestions and recommendations we can test on or see to focus with later when all is astable in priority. | Type `/scan` — text should be blue/accent colored |
| CLR2 | Input | Free text (no /) stays default white | PASS | Type `hello` — text should stay white |
| AI1 | AI | Type `hi` (no API key set) → helpful message, no scan | NOT TESTED → since i have already set my api key i need you to test this directly if you can then we'll mark it PASS.| Type `hi` and press Enter |
| AI2 | AI | Type `hi` with API key set → helpful message, no scan | FAIL → it returns me usage which is also absurd..what do you mean i need to use /ask before i use natural language-thats against the design-or what is /ask used for? because i dont think we have Rag now or need it but if we do i have a stable reference we can just refactor most of the code since it under same rules and language we use. here is the example of the issue; hi there                                                                                                                                                                                                     ┃
┃  AIVAS understands scan commands. Try:                                                                                                                                                                          ┃
┃    /scan 192.168.1.1       — direct scan                                                                                                                                                                        ┃
┃    /ask scan my router      — natural language (with API key)                                                                                                                                                   ┃
┃    /help                    — all commands                                                                                                                                                                      ┃
┃  ❯ /ask hi                                                                                                                                                                                                      ┃
┃  AIVAS understands scan commands. Try:                                                                                                                                                                          ┃
┃    /scan 192.168.1.1       — direct scan                                                                                                                                                                        ┃
┃    /ask scan my router      — natural language (with API key)                                                                                                                                                   ┃
┃    /help                    — all commands     | Type `hi` and press Enter (needs API key configured) |
| OP2 | Output | Two scans in sequence — both visible | FAIL → This does nt work by design since the input section dows not take input is a service is runninning..it actully takes the inputs but does not show them till the report is shown..it then shows them sandwitched! | Run `/scan 192.168.100.253` twice |
| OP3 | Output | `/clear` between scans — second result only | FAIL → /Clear does work but two scans a time does not! | Run scan, `/clear`, run scan again |
| UK3 | Unknown | Bad flag → no crash | FAIL → it just scans! as you can see; /scan 192.168.100.253 --badflagnobody                                                                                                                                                                        ┃
┃  Scanning 192.168.100.253  (level 2)                                                                                                                                                                            ┃
┃  No open services found. 
 | `/scan 192.168.100.253 --badflagnobody` |
| UK4 | Unknown | Paste 500+ chars → no crash | FAIL → It took only soome few lines on the pasted input i tried scrolling horizontally but nothing-we also agreed that the iput should grow vertically not horizontally! | Copy a long block of text and paste into input |
| UK5 | Unknown | Shell injection attempt → no injection | NOT TESTED → Tests this yourself and check then mark if its a pass or not..use the current ip or the normal 127.0.0.1 since networks might have been changed and so on.. | `/scan 192.168.100.253 && echo INJECTED > /tmp/aivas_test` — then check `ls /tmp/aivas_test` (should NOT exist) |

---

ISSUES;
I had this error when i clicked tab soemtime;
 % aivas
╭─────────────────────────────────────────────────────────────────────────────────────── Traceback (most recent call last) ───────────────────────────────────────────────────────────────────────────────────────╮
│ /home/cyberpunk/aivas/aivas/tui/input_actions.py:86 in action_accept_or_cycle                                                                                                                                   │
│                                                                                                                                                                                                                 │
│   83 │   │   inp = self.query_one("#cmd-input", Input)                                        ╭───────────────────────────────────────── locals ─────────────────────────────────────────╮                      │
│   84 │   │   if inp.has_focus and self._accept_suggestion():                                  │  inp = Input(id='cmd-input', classes='-valid')                                           │                      │
│   85 │   │   │   return                                                                       │ self = AIVASApp(title='AIVAS', classes={'-dark-mode'}, pseudo_classes={'dark', 'focus'}) │                      │
│ ❱ 86 │   │   self.focus_next()                                                                ╰──────────────────────────────────────────────────────────────────────────────────────────╯                      │
│   87                                                                                                                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
AttributeError: 'AIVASApp' object has no attribute 'focus_next'

2. we dont need /kev thats complication bcause this should already be auto..if there are kevs they should be shown no need to add extra commands and stress!
3. the validations or else are extremely poor it does not check if the ip is reachable or not so typing any valid formart ip even if its not reachable or not up does a scan and shows; for this example .253 was down!; 
/scan 192.168.100.253                                                                                                                                                                                        ┃
┃  Scanning 192.168.100.253  (level 2)                                                                                                                                                                            ┃
┃  No open services found.

4. the loader seems to be much of an issue, also same for the oytput panel and colors used..so we are gonna do a redesign here on what colors are used(reducing so it does not look as some scriptkidie's puke but professional)-am thinking of using standard loaders used by package managers also removing very bold or strong colors where unnecessary-this i know for a fact most cli tools are cool and not screaming; 
- the loader has to change
- the output structure..before the report-am thinking of not displaying the report directly after its done but creating options when the scan or else is done-either render the report here or provide it in html(a link).
- also for the output or scannig processes we must use/copy from a pure reference so we dont waste time because as of now after a command is run it just shows "scanning..." and nothing else till the report just abruptly pops up!; am thinking of showing every process clearly..whats going on with light animations/movements if possible just as how standard clis or tuis do; i have seen an inspiration from "wapiti" it shows launcing..module..and so on..evrything..if you knnow any best reference..clone it now and follow it-we have not time to waste.
- also on the auto suggestions of commands as a command "/" is being typed..remove the current ui you have added completely because its poor..what i need here is this and i think it does require for the input section(just a single bordered horixzontal line as of now..to be somehow higher or at the same place but flexible such that when a comand is auto suggested(many similar commands show up on the bottom just below the input section with a selector-no need for padding-we can highlight the currently selected command or top one with a different color from the others-and with just an enter a command should be placed on the input section..waiting for other params ot data to be added on it.))
- another issue is that our TUI is still fragile in most cases..forexample..just clicking TAB errored, what else that we still dont know!
- also on the sudo command stabilize it so it works..later on we might think of doing this sudo password confirmation just inside the TUI itself without going back and forth if its possible and unfragile!-recommend here.
- also you can review wapiti report format too since its a html too.
-- i have referenced wapiti for you but if you knw any tool thats opensource and provides proper example for us..clone it aand use it now, my other references i add is the none you know "claude code source code" and the other is here..you can see the loader and selectors and so on..though if possible for the selector use the one in claude code reference or a better one(recommend) here is is "[text](../../../APP-GUIDE-SERVICE/scripts/buntu-cli.py)" if needed you can review the full dir too (some properties are not to be copied-forexampel the use of emojis!.)

## Setup and Launch

| # | Test | Result | Notes |
|---|------|--------|-------|
| L1 | Run `aivas` with no arguments — TUI launches | PASS | |
| L2 | AIVAS ASCII banner renders correctly in the output pane | PASS | |
| L3 | Input bar is visible at the bottom with placeholder hint text | PASS | Does not look like an input bar..more like an end..don't edit it first till we've experimented; can only suggest and recommend on this. |
| L4 | Header shows "AIVAS" title and clock | PASS | |
| L5 | Footer shows Ctrl+C and Ctrl+L keybind hints | PASS | In most TUIs Ctrl+C is not used to exit directly unless with a confirmation or not used at all, since it's mostly used to copy text (Ctrl+Shift+C on Linux, same on Win). These keybinds are close and could stop things without direct intent. |
| L6 | Run `aivas scan --help` (CLI mode) — help text prints and exits | PASS | |
| L7 | Run `aivas doctor` (CLI mode) — doctor output prints and exits | PASS | We spoke of using a first-launch wizard to set things up (API key, local model check). The current `/config` command just shows if things are set — you cannot set things through it since there's no nav in the output pane, which is the right design. Also reviewed Claude's `/doctor` output format — it uses a tree structure (├ └) with version, platform, path, update channel, and an "Enter to continue" pause. |

---

## Input Bar

| # | Test | Result | Notes |
|---|------|--------|-------|
| I1 | Click the input bar — cursor appears, ready to type | PASS | |
| I2 | Type a command — characters appear in the input | PASS | |
| I3 | Press Enter with empty input — nothing happens, no error | PASS | |
| I4 | Press Ctrl+L — output pane clears | PASS | |
| I5 | Press Ctrl+C — TUI exits cleanly | PASS | Should this be allowed? Risk of confusion with copy shortcut. |
| I6 | Type a long command (>80 chars) — input bar scrolls horizontally | FAIL| Input should NOT scroll horizontally — it should grow vertically (next line, no border). Big TUIs do this. Pasting long text should show `[pasted 245 chars]` not the full content. Horizontal scroll is a no — must change. Deferred: big Textual Input change. |
| I7 | After command executes, input clears and cursor returns to input | PASS | |
| ESC1 | ESC during a running scan — scan stops, "Scan cancelled" message appears | FAIL | — does ntohing actually! |
| ESC2 | ESC when no scan is running — input bar loses focus (blurs) | PASS |  — added this sprint |

---

## Tab Autocomplete

| # | Test | Result | Notes |
|---|------|--------|-------|
| TAB1 | Type `/s` — ghost text shows `/scan <target> [--level 1-3] [--udp]` | PASS | But selects only the top command also repeated TAB crashes the TUI. |
| TAB2 | Press Tab to accept suggestion — full command fills in | PASS | But buggy as said on top look into it. |
| TAB3 | Type `/deep` exactly — no ghost text (already complete) | PASS | |
| TAB4 | Type `/xyz` (unknown command) — no suggestion, no crash | PASS | |

---

## /help

| # | Test | Result | Notes |
|---|------|--------|-------|
| H1 | `/help` — lists all available commands | PASS | |
| H2 | `/help scan` — shows usage and description for /scan | PASS | |
| H3 | `/help doctor` — shows usage for /doctor | PASS | |
| H4 | `/HELP` (uppercase) — works the same as `/help` | PASS | |
| H5 | `/help unknowncmd` — does not crash | PASS | |

---

## /doctor

| # | Test | Result | Notes |
|---|------|--------|-------|
| DR1 | `/doctor` — panel renders with check marks | PASS | |
| DR2 | nmap entry shows version string AND AIVAS version shown (e.g. "AIVAS 0.1.0") | PASS (nmap ver) | AIVAS version was missing — fixed this sprint. Re-test. |
| DR3 | Database entry shows CVE count (e.g. "355,307 CVEs") | PASS | |
| DR4 | API key entry shows "not set" when no key configured | PASS | Already gave the key in .env — should set it for aivas too. Not sure how normal users will do it easily. |
| DR5 | API key entry shows "configured" after `/config set api_key ...` | PASS | But am not sure it works for groq or other providers..though we might be good for now as you can see "✓  API key: set (provider: ollama)   " |
| DR6 | Permissions: if setcap done → green tick "nmap has raw socket capability"; if not done → amber warning with exact setcap command | I need you to test this end to end using sudo ..i'll provide you the sudo password to test it because it fails as told on the top issues section. | Was showing "user (--udp needs sudo)". Now fixed to detect setcap and show the one-time fix command. **Sudo design decided: Tier 2 = app.suspend() per-run (default); Tier 1 = setcap (permanent, optional). See notes below table.** |

> **DR6 / Sudo design note:** When a UDP scan is triggered and nmap does not have `cap_net_raw` (setcap not done), AIVAS pauses the TUI, restores the terminal, and prompts for a sudo password directly — the same pattern Claude Code uses (`exitAlternateScreen` → subprocess with `stdio:inherit` → `enterAlternateScreen`). After the scan completes the TUI resumes normally. The user can optionally run the setcap command once to never be prompted again. Setcap security: it grants the raw socket capability to the nmap binary (not to all users as root). Any local user could then run nmap with raw sockets, but only nmap — no file access, no escalation. On a personal machine this is fine. On a shared server it means other local users could also scan networks without sudo logging. For a personal security research tool, setcap is the cleaner choice; the app.suspend() path is the safer default for unknown environments.

---

## /config

| # | Test | Result | Notes |
|---|------|--------|-------|
| CF1 | `/config show` — lists all settings with current values | PASS | |
| CF2 | `/config set provider ollama` — confirms "provider = ollama" | PASS | |
| CF3 | `/config show` after CF2 — shows updated provider | PASS | |
| CF4 | `/config set api_key sk-test123` — confirms, key stored | PASS | |
| CF5 | `/config show` after CF4 — api_key shown as *** | PASS | |
| CF6 | `/config set badkey value` — shows error, does not crash | PASS | |
| CF7 | Exit TUI and relaunch — config values from CF2/CF4 persist | PASS | |

- `narrate` is a config key (true/false) — controls whether AI narration is appended to scan results. Only relevant once LLM narration is confirmed working.

---

## /scan

| # | Test | Result | Notes |
|---|------|--------|-------|
| SC1 | `/scan` with no target — shows usage error | PASS | |
| SC2 | `/scan 192.168.100.253` — scan runs, CVE table appears | PASS | No progress indicator last time — just had to wait. Fixed: now shows progress messages. |
| SC3 | During scan — progress messages visible ("Scanning…", "Found X services — correlating CVEs…") | FAIL → I have provided references we'll use instead of guessing and prototyping. |  |
| SC4 | `/scan 192.168.100.253` — UI remains responsive during scan (can type in input) | PASS | |
| SC-D | Run a second `/scan` while the first is still running — shows "already running" warning | FAIL | 2 Scans at a time are not supported!. |
| SC5 | `/scan 192.168.100.253 --level 1` — completes faster than level 2 | PASS | |
| SC6 | `/scan 192.168.100.253 --level 3` — runs without crash | PASS | |
| SC7 | `/scan 192.168.100.253 --udp` — TUI pauses, sudo password prompt appears in terminal, TUI resumes after scan | FAIL → still does not work as spoken on the above issues section. | Was crashing entirely. Now uses app.suspend() to show sudo password prompt. Re-test. |
| SC8 | `/scan 999.999.999.999` — scan error shown, not "No open services found" | FAIL | nmap should report the bad IP as an error, not silently find nothing. |
| SC9 | `/scan hostname-that-does-not-exist` — error shown, not "no services found" | FAIL | Same issue as SC8. |
| SC10 | KEV-flagged CVEs show [KEV] tag in the output table | FAIL → timing fix | Run `/kev` first, then run a new scan. KEV tags were a timing issue — the previous scan ran before KEV was synced. |
| SC11 | Risk score and grade appear — non-zero, meaningful (e.g. 32/100 Grade D) | PASS (broken) → fixed | Was always 0/F. Fixed: now scores only top 5 findings instead of all 30. Re-test. |
| SC-A | CVE table has `#` row number column (1, 2, 3…) | PASS | NEW |
| SC-B | Score line shows finding count and severity breakdown (e.g. "30 findings (14 critical, 16 high)") | PASS | NEW |
| SC-C | Scan auto-saves; run `/history list` after — scan appears without using `--save` | NOT TESTED | Test this and mark it if it passes. |
| SC12 | Config findings table appears if HTTP service is detected | PASS | Authenticity of results not fully verified. |

> **SC7 / Sudo note:** AIVAS pauses the TUI (Textual `app.suspend()`), shows the sudo prompt in the raw terminal, runs nmap with full privileges, then restores the TUI. The scan output is written to a temp file during the sudo session and cleaned up automatically. If the password is wrong or denied, a clear error is shown. To avoid the prompt entirely, run the setcap command shown in `/doctor`.

> **SC8/SC9 note:** nmap actually accepts and scans invalid IPs/hostnames — it just finds nothing. The "No open services found" message is technically correct but misleading. Needs investigation: does nmap return an error for `999.999.999.999` or silently produce an empty XML? This may be a display issue, not a bug.

> **SC10 / KEV note:** The [KEV] tag code works correctly. CVE-2024-38475 in scan #9 IS in the KEV database. The issue was that the previous scan ran before `update-kev` was ever run. After `/kev` completes, any new scan of .253 should show [KEV] on that CVE.

> **Previous detailed output note (from Round 1):** The output for .253 level 3 showed everything marked CRITICAL/probable and score 0/F — this was the scoring bug (SC11) plus the correlator filtering showing only probable/confirmed matches. All 30 findings being CRITICAL/probable is plausible for a machine with Apache, OpenSSH, and Samba with known CVEs. The data quality concern is noted but needs side-by-side validation against an actual CVE database lookup for those CVEs before concluding it's wrong.

---

## /quick and /deep

| # | Test | Result | Notes |
|---|------|--------|-------|
| QD1 | `/quick 192.168.100.253` — runs level 1 scan | PASS | |
| QD2 | `/quick` with no target — shows usage error | PASS | |
| QD3 | `/deep 192.168.100.253` — runs level 2 WITH UDP (no flag needed) | | FAIL Still udp sudo confimrations fail |
| QD4 | `/deep` with no target — shows usage error | PASS | |

---

## /history

| # | Test | Result | Notes |
|---|------|--------|-------|
| HS1 | `/history list` with no saved scans — shows "no scans saved" message | PASS | |
| HS2 | Run a scan, then `/history list` — scan appears (auto-saved, no `--save` needed) | PASS (with flag) | All scans now auto-save. Re-test without the `--save` flag. |
| HS3 | `/history show 1` — findings from scan #1 render in output pane, no crash | FAIL  | Still crashing. |
| HS4 | `/history show 9999` — "not found" message, no crash | PASS | |
| HS5 | `/history show abc` — "usage" error, no crash | PASS | |
| HS6 | `/history` with no subcommand — defaults to list | PASS | Lists scans briefly, no usage hint shown (that's for /help). |

- On renaming/labelling scans: using numeric IDs (1, 2, 3…) is fine for now. Named reports / HTML+PDF export is a future feature.

---

## /kev (ALL OF THESE FAIL I NEED YOU TO TEST AND FIX THEM ALL)

| # | Test | Result | Notes |
|---|------|--------|-------|
| KV1 | `/kev` — "Downloading CISA KEV feed…" message appears, then completes | FAIL → fixed | Was crashing: SQLite thread error. Fixed: HTTP fetch runs in thread, DB write runs on main thread. Re-test. |
| KV2 | `/kev` — completes with count of CVEs marked (e.g. "1612 CVEs marked as exploited in wild") | FAIL → fixed | Was blocked by KV1. Re-test. |
| KV3 | `/kev` with no internet (turn off wifi, then run) — shows error message, no crash | FAIL → re-test | Was blocked by KV1. Re-test. |
| KV4 | `/kev` a second time in same session — completes without errors or duplicates | FAIL → re-test | Was blocked by KV1. Re-test. |

> **What is KEV?** CISA (US Cybersecurity and Infrastructure Security Agency) maintains a public list of CVEs that are actively being exploited in real-world attacks — the Known Exploited Vulnerabilities catalog. When AIVAS finds a CVE in your scan that is on this list, it adds a [KEV] tag in the findings table and will eventually highlight it in reports. The list has ~1,600 CVEs. Running `/kev` downloads the latest list and marks those CVEs in your local database.

---

## /clear and /exit

| # | Test | Result | Notes |
|---|------|--------|-------|
| CL1 | `/clear` — output pane empties | PASS | Auto-clear not needed: the output is a log, not a chat. When LLM narration comes, we won't need RAG for the TUI — narration just appends to the output pane. |
| CL2 | `/clear` — input remains focused after clearing | PASS | |
| CL3 | `/exit` — TUI closes cleanly | PASS | |

---

## Free Text and AI Routing (I NEED YOU TO FIX AND TEST THIS PART SEVERELY NOW.)

> **Status: BLOCKED — needs internal testing before manual re-test.** All AI scenarios were skipped because the feature was buggy. Internal testing of intent parsing (Groq + Ollama) must be done and confirmed before this section is opened for manual testing.

| # | Test | Result | Notes |
|---|------|--------|-------|
| AI1 | Type plain text with no API key — shows "No API key configured" message | | Test this one only (no API key path is safe to test now) |
| AI2 | Message includes suggestion to use `/scan` or `/doctor` | | Test alongside AI1 |
| AI3 | With API key: type "scan the ASUS machine for web vulnerabilities" — AI parses and runs scan | | BLOCKED — internal testing first |
| AI4 | With API key: partial/ambiguous query — clarifies or scans | | BLOCKED |
| AI5 | With API key: AI call fails (bad key) — error shown, no crash | | BLOCKED |

---

## Output Panel Behavior

| # | Test | Result | Notes |
|---|------|--------|-------|
| OP1 | Long CVE table (20+ rows) — output pane scrolls | PASS | |
| OP2 | Run two scans in sequence — both results visible, not overwritten | NOT TESTED | The output pane is a log — each command appends below the last. This is correct. No collapse/minimize needed for this version since we don't have extensive agent operations. |
| OP3 | `/clear` between scans — second scan result is the only visible content | NOT TESTED | |
| OP4 | Output from `/doctor` followed by `/scan` — both visible, clearly separated | PASS | |
| OP5 | Very long description text wraps within the table column | PASS | |
| OP6 | Colors render correctly (CRITICAL red, HIGH yellow, [KEV] magenta) | PASS | |
| OP7 | Output is scrollable with mouse wheel | PASS | |
| OP8 | Output is scrollable with keyboard (Page Up / Page Down) | PASS | |

---

## Unknown and Invalid Commands

| # | Test | Result | Notes |
|---|------|--------|-------|
| UK1 | `/randomcommand` — "Unknown command" message shown | PASS | |
| UK2 | `/` alone (no command name) — no crash | PASS | |
| UK3 | `/scan 192.168.100.253 --badflagnobody` — handles gracefully, no crash | NOT TESTED | Try this exact command. |
| UK4 | Paste 500+ characters into input — no crash | NOT TESTED | Paste a long string (copy from a text file). |
| UK5 | `/scan 192.168.100.253 && echo INJECTED > /tmp/aivas_test` — no shell injection | NOT TESTED | Create `/tmp/aivas_test` check: `ls /tmp/aivas_test` should NOT exist after running. AIVAS passes args as a list to subprocess, not through a shell — injection should be impossible. |

---

## CLI Compatibility (aivas subcommands still work)

| # | Test | Result | Notes |
|---|------|--------|-------|
| CL1 | `aivas scan 192.168.100.253` — runs scan from terminal, no TUI | PASS | |
| CL2 | `aivas doctor` — health check output, no TUI | PASS | |
| CL3 | `aivas config show` — prints config, no TUI | PASS | |
| CL4 | `aivas history list` — prints history table, no TUI | PASS | |
| CL5 | `aivas --help` — shows all commands | PASS | |
| CL6 | `aivas update-kev` — syncs KEV feed from terminal | PASS | Worked here but not in the TUI (KV1 crash). CLI uses a separate code path that doesn't have the thread issue. Auto-sync on startup is a design question — leave manual for now; auto-sync if last sync > 7 days is a future option. |

---

## Terminal Compatibility

| # | Terminal | Test | Result | Notes |
|---|----------|------|--------|-------|
| TC1 | GNOME Terminal | TUI launches, renders correctly | PASS | |
| TC2 | Zsh default terminal (ASUS TUF) | TUI launches, renders correctly | PASS | |
| TC3 | tmux | `tmux new-session` → `aivas` — TUI renders without corruption | NOT TESTED | `tmux` is a terminal multiplexer — splits your terminal into panes. Install: `sudo apt install tmux`. Then: `tmux`, then run `aivas`. |
| TC4 | SSH session | TUI renders remotely | NOT TESTED | Requires SSH access to the machine from another device. Deferred — not a priority for the diploma demo. |
| TC5 | Small terminal window (80x24) | Layout does not break | PASS | |
| TC6 | Wide terminal (220+ cols) | Layout does not stretch unusably | PASS | A thin empty strip remains at the very bottom even in fullscreen (F11). Likely Ubuntu/GNOME chrome adding a panel, not AIVAS. Confirm on another machine or in tmux fullscreen. |

---

## Deferred Items

| # | Item | Notes |
|---|------|-------|
| DEF-01 | First-run setup wizard (API key prompt, nmap check, setcap suggestion on first launch) | Sprint 2i |
| DEF-02 | Tab autocomplete for slash commands | **DONE this sprint** — inline ghost text via Textual Suggester |
| DEF-03 | Markdown rendering of narration output inside TUI | After narration integration confirmed working — keeps debugging concerns separate |
| DEF-04 | `/scan --save` option (prompt to save) | Removed — all scans now auto-save |
| DEF-05 | Textual Web mode (browser GUI) | Post-diploma |
| DEF-06 | Mouse click on CVE row to expand full description | Polish pass |
| DEF-07 | Level 2 active CVE verification probes | Post-diploma |
| DEF-08 | Swahili narration rendering in output pane | After narration integration — depends on user's selected language |
| DEF-09 | `pip install aivas` from PyPI | After v1.0.0 tag |
| DEF-10 | Input bar: vertical growth (multi-line) + paste truncation `[pasted N chars]` | Sprint 2i — I6 is a known design issue, big Textual change |
| DEF-11 | Command history navigation (up/down arrows in input) | Sprint 2i |

---

_Checklist version: 2026-06-08 rev 3 (Round 3 — dropdown, history, ESC priority, SC7 suspend fix, SC8/SC9 validation, intent guard, color reduction)_
