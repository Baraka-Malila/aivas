"""LLM-cached per-CVE remediation advice (EN + SW)."""
from __future__ import annotations

import asyncio
import logging
import sqlite3

from aivas.narrator.providers import GroqProvider

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "llama-3.1-8b-instant"

_PROMPT = """\
You are a security engineer producing concise, ACTIONABLE remediation advice for a single CVE.

CVE: {cve_id}
CVSS: {cvss_score} ({cvss_severity})
Description: {description}

Output two short paragraphs, separated by a blank line.

Paragraph 1 — ENGLISH:
3-5 sentences. Lead with the specific software/version to upgrade to. Name compensating controls (firewall rule, config setting, disabled feature) the admin can apply TODAY if upgrade is impossible. End with one sentence on detection (log location, IOC, network signature) if relevant.

Paragraph 2 — KISWAHILI:
Same content as paragraph 1, rendered in Kiswahili. Use clear, plain language a Tanzanian IT admin would understand. Keep CVE IDs, version numbers, and product names in their original Latin form.

Do not output headings, bullets, or markdown. Two paragraphs. That is the whole output.
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
) -> tuple[str, str]:
    """Call Groq once. Returns (advice_en, advice_sw)."""
    provider = GroqProvider(api_key=api_key, model=_DEFAULT_MODEL)
    prompt = _PROMPT.format(
        cve_id=cve_id,
        cvss_score=cve_row.get("cvss_score") or "N/A",
        cvss_severity=cve_row.get("cvss_severity") or "N/A",
        description=(cve_row.get("description") or "")[:600],
    )
    text = await asyncio.to_thread(provider.generate, prompt)
    return _parse_two_paragraphs(text)


async def warm_cache(
    conn: sqlite3.Connection, cve_ids: list[str], api_key: str,
    max_concurrent: int = 5,
) -> None:
    """For each cve_id not yet cached, generate + store advice. Bounded concurrency.
       Silent on per-CVE errors; the legacy template covers misses."""
    if not api_key:
        return
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

    async def _one(cve_id: str, row: dict):
        async with sem:
            try:
                en, sw = await generate_advice(cve_id, row, api_key)
                if en:
                    put_advice(conn, cve_id, en, sw, _DEFAULT_MODEL)
            except Exception as exc:
                logger.warning("cve_advice failed for %s: %s", cve_id, exc)

    await asyncio.gather(*(_one(c, r) for c, r in needed))
