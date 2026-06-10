"""AI dispatch: intent parsing, narration, session context."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp

_SYSTEM_PROMPT = """\
You are AIVAS, a network security scanner assistant for small businesses in Tanzania.
Keep responses under 3 sentences. Only answer questions about network security and scan results.
If asked about anything unrelated, redirect the user to scanning.
Detect the user language: if they write in Swahili, respond in Swahili. Otherwise English.\
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

    context = build_context(getattr(app, "_scan_history", []))
    prompt = f"{context}\n\nUser: {text}"
    try:
        response = await asyncio.to_thread(_call_groq, api_key, prompt)
        app.tui_print(f"[dim]AIVAS:[/dim] {response}")
    except Exception as exc:
        s = str(exc)
        if "401" in s or "invalid_api_key" in s.lower():
            app.tui_print(
                "[#e53935]AI:[/#e53935] Invalid API key — update with "
                "[bold]/config set api_key YOUR_KEY[/bold]"
            )
        else:
            app.tui_print(f"[#e53935]AI error:[/#e53935] {exc}")


async def narrate_findings(app: "AIVASApp", findings: list[dict],
                            api_key: str, lang: str = "en") -> None:
    """Call narrator on top 5 findings, display in output pane."""
    from aivas.narrator.narrator import narrate
    from aivas.narrator.providers import GroqProvider
    from aivas.formatting import print_narrations
    from io import StringIO
    from rich.console import Console

    app.tui_print("[dim]Generating AI narration (top 5 findings)...[/dim]")
    try:
        prov = GroqProvider(api_key=api_key)
        enriched = await asyncio.to_thread(narrate, findings[:5], prov)
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
