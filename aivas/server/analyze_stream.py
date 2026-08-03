"""Streaming analysis for ScanCard — emits NDJSON events like the chat WebSocket."""
from __future__ import annotations

import json
import logging
import sqlite3

_log = logging.getLogger("aivas.analyze")

_LANG_DIRECTIVE = {
    "auto": "Detect context and respond in English unless clearly another language.",
    "en": "Always respond in English.",
    "sw": "Always respond in Swahili (Kiswahili).",
}

_PROVIDER_DEFAULTS = {
    "groq": "llama-3.1-8b-instant",
    "claude": "claude-haiku-4-5-20251001",
    "ollama": "llama3",
}


def _ev(obj: dict) -> str:
    return json.dumps(obj) + "\n"


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("cvss_severity") or "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _findings_summary(findings: list[dict]) -> str:
    counts = _severity_counts(findings)
    parts = [f"{v} {k.lower()}" for k, v in counts.items() if v > 0]
    kev_count = sum(1 for f in findings if f.get("kev"))
    base = f"{len(findings)} finding{'s' if len(findings) != 1 else ''}"
    if parts:
        base += f" ({', '.join(parts)})"
    if kev_count:
        base += f", {kev_count} KEV"
    return base


def _build_risk_prompt(meta: dict, findings: list[dict]) -> str:
    grade = (meta.get("grade") or "?").replace("Grade ", "")
    target = meta.get("target", "unknown")
    counts = _severity_counts(findings)
    kev_count = sum(1 for f in findings if f.get("kev"))

    top = max(findings, key=lambda x: x.get("cvss_score") or 0, default=None)
    top_line = ""
    if top:
        kev_note = ", actively exploited in the wild" if top.get("kev") else ""
        top_line = (
            f"Most dangerous: {top['cve_id']} "
            f"(CVSS {top.get('cvss_score', '?')}, {top.get('cvss_severity', '?')}{kev_note}) "
            f"— {(top.get('description') or '')[:200]}"
        )

    count_str = ", ".join(f"{v} {k.lower()}" for k, v in counts.items() if v > 0)
    kev_str = f", {kev_count} actively exploited" if kev_count > 0 else ""

    return (
        f"Scan data: target={target}, grade={grade}, "
        f"{len(findings)} findings ({count_str}{kev_str}).\n"
        f"{top_line}\n\n"
        "Write a 3-paragraph executive risk brief for a non-technical business owner. "
        "No lists. No headers. Exactly three paragraphs, each under 4 sentences.\n\n"
        "Paragraph 1 — Security Posture: State the grade and what it means in plain language "
        "(not jargon). Give the finding count by severity in one sentence.\n\n"
        "Paragraph 2 — Primary Threat: Name the most dangerous vulnerability — what software "
        "it affects, what an attacker can do, whether it is actively exploited right now.\n\n"
        "Paragraph 3 — Action: What the business owner must do in the next 24 hours, and "
        "roughly how long it takes. Write as if speaking to a shop owner, not a sysadmin — "
        "no commands, no package names, no acronyms."
    )


def _build_remediation_prompt(meta: dict, findings: list[dict]) -> str:
    target = meta.get("target", "unknown")

    sorted_f = sorted(
        findings,
        key=lambda x: (not x.get("kev"), -(x.get("cvss_score") or 0)),
    )

    lines = []
    for f in sorted_f:
        sev = (f.get("cvss_severity") or "LOW").upper()
        kev = " ⚠ KEV" if f.get("kev") else ""
        score = f.get("cvss_score", "?")
        desc = (f.get("description") or "")[:120]
        lines.append(f"  {f['cve_id']} [{sev}{kev}] CVSS={score} — {desc}")

    findings_block = "\n".join(lines) if lines else "  No findings."

    return (
        f"Target: {target}\n"
        f"Findings ({len(findings)} total):\n{findings_block}\n\n"
        "Write a priority-ordered remediation plan for a Linux sysadmin. "
        "Group under severity headers (## CRITICAL, ## HIGH, ## MEDIUM, ## LOW). "
        "Under each header, use a numbered list. For each CVE:\n"
        "  1. CVE ID\n"
        "  2. Affected software and version currently installed (if known)\n"
        "  3. EXACT version that fixes it — not 'latest', a specific release number. "
        "If truly unknown, say 'Fixed version unknown — upgrade to latest stable.'\n"
        "  4. One concrete action: exact apt/dnf/pip command or specific config change\n\n"
        "Omit severity groups with zero findings. Cover every finding."
    )


async def stream_analysis(
    conn: sqlite3.Connection,
    scan_id: int,
    analysis_type: str,
    provider_name: str,
    model: str | None,
    api_key: str | None,
    lang: str = "auto",
):
    """Yield newline-delimited JSON events compatible with the chat WebSocket protocol."""
    from aivas.history import get_scan_meta, get_scan_findings
    from aivas.narrator.providers.factory import get_provider

    # Show tool call
    yield _ev({"type": "tool_call", "name": "get_scan_findings", "args": {"scan_id": scan_id}})

    meta = get_scan_meta(conn, scan_id)
    if meta is None:
        yield _ev({"type": "error", "text": "Scan not found."})
        return

    findings = get_scan_findings(conn, scan_id)

    # Show tool result
    yield _ev({
        "type": "tool_result",
        "name": "get_scan_findings",
        "summary": _findings_summary(findings),
    })

    if analysis_type == "risk_summary":
        user_prompt = _build_risk_prompt(meta, findings)
        system = (
            "You are a concise security advisor writing executive briefs. "
            "Be clear, direct, and avoid technical jargon. "
            "Follow the paragraph structure exactly as instructed."
        )
        max_tokens = 420
    else:
        user_prompt = _build_remediation_prompt(meta, findings)
        system = (
            "You are a Linux sysadmin writing precise remediation checklists. "
            "Be specific about versions and commands. "
            "Use ## severity headers and numbered lists exactly as instructed."
        )
        max_tokens = 900

    lang_note = _LANG_DIRECTIVE.get(lang) or _LANG_DIRECTIVE["auto"]
    messages = [
        {"role": "system", "content": f"{system}\n\n{lang_note}"},
        {"role": "user", "content": user_prompt},
    ]

    chosen_model = model or _PROVIDER_DEFAULTS.get(provider_name, "llama-3.1-8b-instant")

    try:
        provider = get_provider(provider_name, model=chosen_model, api_key=api_key)
    except ValueError as exc:
        yield _ev({"type": "error", "text": str(exc)})
        return

    try:
        async for token in provider.stream(messages, max_tokens=max_tokens):
            yield _ev({"type": "token", "text": token})
    except Exception as exc:
        _log.error("analyze_stream error [%s]: %s", analysis_type, exc)
        s = str(exc)
        if "429" in s or "rate_limit" in s.lower():
            yield _ev({"type": "token", "text": "\n\n*Rate limit reached — please wait a moment.*"})
        else:
            yield _ev({"type": "error", "text": str(exc)})

    yield _ev({"type": "done"})
