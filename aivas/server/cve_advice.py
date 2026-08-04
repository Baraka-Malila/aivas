"""LLM-cached per-CVE remediation advice (EN + SW)."""
from __future__ import annotations

import asyncio
import logging
import sqlite3

logger = logging.getLogger(__name__)

_PROVIDER_DEFAULTS = {
    "groq":    "llama-3.1-8b-instant",
    "mistral": "mistral-small-latest",
    "ollama":  "llama3",
}

_PROMPT = """\
You are a security engineer writing concise remediation advice for a single CVE for a PDF report table cell.

CVE: {cve_id}
CVSS: {cvss_score} ({cvss_severity})
Description: {description}

Output exactly two paragraphs separated by a blank line. No headings, bullets, or markdown.

Paragraph 1 — ENGLISH (2 sentences MAX):
Sentence 1: Name the EXACT patched version to upgrade to (e.g. "Upgrade to OpenSSH 9.8p1").
Sentence 2: One compensating control if upgrade is impossible (firewall rule, config change, disabled feature).

Paragraph 2 — KISWAHILI (2 sentences MAX):
Same content as paragraph 1 in Kiswahili. Keep CVE IDs, version numbers, and product names in Latin form.

CRITICAL: 2 sentences each paragraph. No more.
"""


def get_advice(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    row = conn.execute(
        "SELECT cve_id, advice_en, advice_sw, model, created_at "
        "FROM cve_advice WHERE cve_id=?",
        (cve_id,),
    ).fetchone()
    return dict(row) if row else None


def put_advice(
    conn: sqlite3.Connection, cve_id: str,
    advice_en: str, advice_sw: str, model: str,
) -> None:
    conn.execute(
        "INSERT INTO cve_advice(cve_id, advice_en, advice_sw, model) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET "
        "advice_en=excluded.advice_en, advice_sw=excluded.advice_sw, "
        "model=excluded.model, created_at=CURRENT_TIMESTAMP",
        (cve_id, advice_en, advice_sw, model),
    )
    conn.commit()


def _parse_two_paragraphs(text: str) -> tuple[str, str]:
    parts = text.strip().split("\n\n", 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""


async def generate_advice(
    cve_id: str, cve_row: dict, api_key: str,
    provider_name: str = "groq", model: str | None = None,
) -> tuple[str, str]:
    """Call LLM once. Returns (advice_en, advice_sw)."""
    from aivas.narrator.providers.factory import get_provider
    chosen_model = model or _PROVIDER_DEFAULTS.get(provider_name, "llama-3.1-8b-instant")
    provider = get_provider(provider_name, model=chosen_model, api_key=api_key)
    prompt = _PROMPT.format(
        cve_id=cve_id,
        cvss_score=cve_row.get("cvss_score") or "N/A",
        cvss_severity=cve_row.get("cvss_severity") or "N/A",
        description=(cve_row.get("description") or "")[:600],
    )
    text = await asyncio.to_thread(provider.generate, prompt, 800)
    return _parse_two_paragraphs(text)


async def warm_cache(
    conn: sqlite3.Connection, cve_ids: list[str], api_key: str,
    provider_name: str = "groq", model: str | None = None,
    max_concurrent: int = 3,
) -> None:
    """For each cve_id not yet cached, generate + store advice. Bounded concurrency.
       Silent on per-CVE errors; the legacy template covers misses."""
    if not api_key:
        return
    chosen_model = model or _PROVIDER_DEFAULTS.get(provider_name, "llama-3.1-8b-instant")
    needed: list[tuple[str, dict]] = []
    for cve_id in cve_ids:
        if get_advice(conn, cve_id):
            continue
        row = conn.execute(
            "SELECT cve_id, cvss_score, cvss_severity, description "
            "FROM cves WHERE cve_id=?",
            (cve_id,),
        ).fetchone()
        if not row:
            continue
        needed.append((cve_id, dict(row)))
    if not needed:
        return

    sem = asyncio.Semaphore(max_concurrent)

    # Groq free tier: ~30 RPM / ~6000 TPM for llama-3.1-8b-instant.
    # With ~150 tokens per advice call, 2.5s gap keeps us safely under the limit.
    _groq_delay = 2.5 if provider_name == "groq" else 0.0

    async def _one(cve_id: str, row: dict):
        async with sem:
            try:
                en, sw = await generate_advice(cve_id, row, api_key, provider_name=provider_name, model=chosen_model)
                if en:
                    put_advice(conn, cve_id, en, sw, f"{provider_name}/{chosen_model}")
            except Exception as exc:
                logger.warning("cve_advice failed for %s: %s", cve_id, exc)
            if _groq_delay:
                await asyncio.sleep(_groq_delay)

    await asyncio.gather(*(_one(c, r) for c, r in needed))
