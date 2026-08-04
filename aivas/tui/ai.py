"""AI dispatch: Groq agent (with tools) or Ollama Q&A fallback."""
from __future__ import annotations

import asyncio
import os
import re
import socket
from typing import TYPE_CHECKING

_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b')

if TYPE_CHECKING:
    from .app import AIVASApp

_SYSTEM_PROMPT = """\
You are AIVAS, a network security assistant for small businesses.
Always respond in English. Keep responses under 3 sentences.
Only answer questions about network security.\
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


def _print_ai(app: "AIVASApp", text: str, label: str = "AIVAS") -> None:
    """Render an AI response with Markdown formatting."""
    from rich.markdown import Markdown
    app.tui_print(f"\n[#888888]{label}:[/#888888]")
    if text.strip():
        app.tui_print(Markdown(text.strip()))
    app.tui_print("")


def _try_direct_scan(app: "AIVASApp", text: str) -> bool:
    """If text contains a scan intent + IP, launch scan directly. Returns True if launched."""
    from .commands import _SCAN_INTENT_RE
    if not _SCAN_INTENT_RE.search(text):
        return False
    m = _IP_RE.search(text)
    if not m:
        return False
    from .scan import run_scan_pipeline
    app.tui_print("[#888888]AI unavailable — running scan directly.[/#888888]")
    app.run_worker(run_scan_pipeline(app, m.group(1), 2), exclusive=True)
    return True


async def dispatch(
    app: "AIVASApp",
    text: str,
    api_key: str | None,
    provider: str = "groq",
    shodan_key: str | None = None,
) -> None:
    """Route free text: normalize → agent → Ollama Q&A → direct scan fallback."""
    text = _normalize(text)
    context = build_context(getattr(app, "_scan_history", []))
    _rate_limited = False
    _rate_wait = ""

    # Cloud provider selected but no key configured — stop here with a clear message
    if not api_key and provider in ("groq", "mistral"):
        key_cmd = "mistral_api_key" if provider == "mistral" else "api_key"
        app.tui_print(
            f"\n[#fdd835]No API key configured for {provider}.[/#fdd835]\n"
            f"[#888888]Set one:  [bold]/config set {key_cmd} YOUR_KEY[/bold]\n"
            f"Or use local Ollama:  [bold]/switch ollama[/bold][/#888888]\n"
        )
        return

    use_local = not api_key  # True only when provider is "ollama" (no key expected)

    if api_key:
        from .agent import run_agent
        _busy = getattr(app, 'set_busy', None)
        _idle = getattr(app, 'set_scan_idle', None)
        if _busy:
            _busy("AIVAS thinking…")
        try:
            history = getattr(app, '_chat_history', [])
            response, scan_intent, turns = await run_agent(
                app, text, api_key, provider=provider, shodan_key=shodan_key,
                context=context, history=history,
            )
            app._chat_history = (history + turns)[-12:]
            if response:
                _print_ai(app, response)
            if scan_intent:
                from .scan import run_scan_pipeline
                app.run_worker(
                    run_scan_pipeline(app, scan_intent[0], scan_intent[1]),
                    exclusive=True,
                )
            return
        except Exception as exc:
            s = str(exc)
            if "401" in s or "invalid_api_key" in s.lower() or "Unauthorized" in s:
                key_cmd = "mistral_api_key" if provider == "mistral" else "api_key"
                app.tui_print(
                    f"\n[#888888]{provider.title()} key rejected — falling back to local model.[/#888888]\n"
                    f"[#888888]Fix: [bold]/config set {key_cmd} YOUR_KEY[/bold][/#888888]"
                )
                use_local = True
            elif "429" in s or "rate_limit" in s.lower():
                _rate_limited = True
                m = re.search(r'try again in (\S+)', s, re.IGNORECASE)
                _rate_wait = f" Retry in {m.group(1)}." if m else ""
            else:
                app.tui_print(f"\n[#e53935]AI error:[/#e53935] {exc}\n")
                return
        finally:
            if _idle:
                _idle()

    if _rate_limited:
        from aivas import config as _cfg_rl
        mistral_key = _cfg_rl.load().get("mistral_api_key") or os.environ.get("MISTRAL_API_KEY")
        if mistral_key and provider != "mistral":
            app.tui_print(
                f"\n[#fdd835]Rate limit ({provider}).{_rate_wait}[/#fdd835]"
                "  [#888888]Auto-switching to Mistral…[/#888888]"
            )
            from .agent import run_agent as _run_agent2
            _busy2 = getattr(app, 'set_busy', None)
            _idle2 = getattr(app, 'set_scan_idle', None)
            if _busy2:
                _busy2("AIVAS thinking (Mistral)…")
            try:
                history2 = getattr(app, '_chat_history', [])
                response2, scan_intent2, turns2 = await _run_agent2(
                    app, text, mistral_key, provider="mistral",
                    shodan_key=shodan_key, context=context, history=history2,
                )
                app._chat_history = (history2 + turns2)[-12:]
                if response2:
                    _print_ai(app, response2)
                if scan_intent2:
                    from .scan import run_scan_pipeline as _rsp2
                    app.run_worker(_rsp2(app, scan_intent2[0], scan_intent2[1]), exclusive=True)
                return
            except Exception as mexc:
                ms = str(mexc)
                if "429" in ms:
                    app.tui_print("\n[#fdd835]Mistral also rate limited. Try again later.[/#fdd835]\n")
                else:
                    app.tui_print(f"\n[#e53935]Mistral fallback failed:[/#e53935] {mexc}\n")
            finally:
                if _idle2:
                    _idle2()
            return
        else:
            app.tui_print(
                f"\n[#fdd835]Rate limit reached.{_rate_wait}[/#fdd835]\n"
                "[#888888]Quick fix: [bold]/switch mistral[/bold]"
                "  or  [bold]/switch ollama[/bold][/#888888]\n"
            )
            return

    if use_local:
        prompt = f"{context}\n\nUser: {text}"
        try:
            response = await asyncio.to_thread(_call_local, prompt)
            _print_ai(app, response, label="AIVAS (local)")
            return
        except Exception:
            pass  # Ollama not running — try direct scan

    if not _try_direct_scan(app, text):
        if api_key:
            app.tui_print("[#888888]Both Groq and local model unavailable. Try /scan <target> directly.[/#888888]")
        else:
            app.tui_print(
                "[#888888]No AI configured and no local model running.\n"
                "Set a key: [bold]/config set api_key YOUR_KEY[/bold]  "
                "or start Ollama for offline use.[/#888888]"
            )


async def narrate_findings(app: "AIVASApp", findings: list[dict],
                            api_key: str | None, lang: str = "en") -> None:
    """Narrate top 5 findings via Groq (or local llama3 fallback)."""
    from aivas.narrator.narrator import narrate
    from aivas.narrator.providers import GroqProvider, OllamaProvider
    from aivas.formatting import print_narrations

    src = "Groq" if api_key else "local model"
    app.tui_print(f"[#888888]Generating AI narration ({src})...[/#888888]")
    _busy = getattr(app, 'set_busy', None)
    _idle = getattr(app, 'set_scan_idle', None)
    if _busy:
        _busy("Generating narration…")
    try:
        prov = GroqProvider(api_key=api_key) if api_key else OllamaProvider(model="llama3")
        enriched = await asyncio.to_thread(narrate, findings[:5], prov)
        print_narrations(enriched, lang=lang, print_fn=app.tui_print)
    except Exception as exc:
        app.tui_print(f"[#e53935]Narration failed:[/#e53935] {exc}")
    finally:
        if _idle:
            _idle()


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
