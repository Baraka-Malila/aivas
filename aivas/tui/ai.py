"""AI dispatch: Groq agent (with tools) or Ollama Q&A fallback."""
from __future__ import annotations

import asyncio
import re
import socket
from typing import TYPE_CHECKING

_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b')

if TYPE_CHECKING:
    from .app import AIVASApp

_SYSTEM_PROMPT = """\
You are AIVAS, a network security assistant for small businesses in Tanzania.
Keep responses under 3 sentences. Only answer questions about network security.
If the user writes in Swahili, respond in Swahili. Otherwise English.\
"""

_LOCAL_RE = re.compile(
    r'\b(this\s+(pc|machine|computer|server|device)|my\s+(pc|machine|computer)'
    r'|localhost|this\s+host'
    r'|kompyuta\s+hii|mashine\s+hii|seva\s+hii|kifaa\s+hii'   # Swahili: "this computer/machine/server/device"
    r'|hii\s+kompyuta|hii\s+mashine|kompyuta\s+yangu'          # Swahili: "this/my computer"
    r')\b',
    re.IGNORECASE,
)


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _normalize(text: str) -> str:
    return _LOCAL_RE.sub(_local_ip(), text)


def build_context(scan_history: list[dict]) -> str:
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


def _try_direct_scan(app: "AIVASApp", text: str) -> bool:
    """If text contains a scan intent + IP, launch scan directly. Returns True if launched."""
    from .commands import _SCAN_INTENT_RE
    if not _SCAN_INTENT_RE.search(text):
        return False
    m = _IP_RE.search(text)
    if not m:
        return False
    from .scan import run_scan_pipeline
    app.tui_print("[dim]AI unavailable — running scan directly.[/dim]")
    app.run_worker(run_scan_pipeline(app, m.group(1), 2), exclusive=True)
    return True


async def dispatch(app: "AIVASApp", text: str, api_key: str | None) -> None:
    """Route free text: normalize → Groq agent → Ollama Q&A → direct scan fallback."""
    text = _normalize(text)
    context = build_context(getattr(app, "_scan_history", []))
    use_local = not api_key

    if api_key:
        from .agent import run_agent
        _busy = getattr(app, 'set_busy', None)
        _idle = getattr(app, 'set_scan_idle', None)
        if _busy: _busy("AIVAS thinking…")
        try:
            response, scan_intent = await run_agent(app, text, api_key, context=context)
            if response:
                app.tui_print(f"[dim]AIVAS:[/dim] {response}")
            if scan_intent:
                from .scan import run_scan_pipeline
                app.run_worker(
                    run_scan_pipeline(app, scan_intent[0], scan_intent[1]),
                    exclusive=True,
                )
            return
        except Exception as exc:
            s = str(exc)
            if "401" in s or "invalid_api_key" in s.lower():
                app.tui_print(
                    "[dim]Groq key rejected — falling back to local model.[/dim]\n"
                    "[dim]Fix: [bold]/config set api_key YOUR_KEY[/bold][/dim]"
                )
                use_local = True
            else:
                app.tui_print(f"[#e53935]AI error:[/#e53935] {exc}")
                return
        finally:
            if _idle: _idle()

    if use_local:
        prompt = f"{context}\n\nUser: {text}"
        try:
            response = await asyncio.to_thread(_call_local, prompt)
            app.tui_print(f"[dim]AIVAS (local):[/dim] {response}")
            return
        except Exception:
            pass  # Ollama not running — try direct scan

    if not _try_direct_scan(app, text):
        if api_key:
            app.tui_print("[dim]Both Groq and local model unavailable. Try /scan <target> directly.[/dim]")
        else:
            app.tui_print(
                "[dim]No AI configured and no local model running.\n"
                "Set a key: [bold]/config set api_key YOUR_KEY[/bold]  "
                "or start Ollama for offline use.[/dim]"
            )


async def narrate_findings(app: "AIVASApp", findings: list[dict],
                            api_key: str | None, lang: str = "en") -> None:
    """Narrate top 5 findings via Groq (or local llama3 fallback)."""
    from aivas.narrator.narrator import narrate
    from aivas.narrator.providers import GroqProvider, OllamaProvider
    from aivas.formatting import print_narrations

    src = "Groq" if api_key else "local model"
    app.tui_print(f"[dim]Generating AI narration ({src})...[/dim]")
    _busy = getattr(app, 'set_busy', None)
    _idle = getattr(app, 'set_scan_idle', None)
    if _busy: _busy("Generating narration…")
    try:
        prov = GroqProvider(api_key=api_key) if api_key else OllamaProvider(model="llama3")
        enriched = await asyncio.to_thread(narrate, findings[:5], prov)
        print_narrations(enriched, lang=lang, print_fn=app.tui_print)
    except Exception as exc:
        app.tui_print(f"[#e53935]Narration failed:[/#e53935] {exc}")
    finally:
        if _idle: _idle()


def _call_local(user_msg: str) -> str:
    import requests
    payload = {
        "model": "llama3",
        "prompt": _SYSTEM_PROMPT + "\n\n" + user_msg,
        "stream": False,
    }
    resp = requests.post("http://localhost:11434/api/generate", json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()["response"].strip()
