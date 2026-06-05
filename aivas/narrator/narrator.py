import json
import logging
from typing import Protocol

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """\
You are a cybersecurity expert writing a vulnerability assessment report for a small \
business in Tanzania. Write a brief risk narration (2-3 sentences) for this CVE in \
both English and Swahili. Use plain language that a non-technical IT manager can understand.

CVE ID: {cve_id}
CVSS Score: {cvss_score} ({cvss_severity})
Description: {description}

Respond ONLY with valid JSON — no markdown, no explanation:
{{"en": "2-3 sentence risk explanation in English.", \
"sw": "Maelezo ya hatari kwa Kiswahili (2-3 sentensi).", \
"fix_en": "One sentence fix instruction in English.", \
"fix_sw": "Hatua moja ya kutatua tatizo kwa Kiswahili."}}"""


class LLMProvider(Protocol):
    def generate(self, prompt: str) -> str: ...


def _parse_narration(text: str) -> dict[str, str]:
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start:end])
            if "en" in data and "sw" in data:
                return {
                    "en": str(data.get("en", "")),
                    "sw": str(data.get("sw", "")),
                    "fix_en": str(data.get("fix_en", "")),
                    "fix_sw": str(data.get("fix_sw", "")),
                }
        except json.JSONDecodeError:
            pass
    return {"en": "", "sw": "", "fix_en": "", "fix_sw": ""}


def narrate(findings: list[dict], provider: LLMProvider) -> list[dict]:
    result = []
    for f in findings:
        enriched = dict(f)
        try:
            prompt = PROMPT_TEMPLATE.format(
                cve_id=f["cve_id"],
                cvss_score=f.get("cvss_score") or "N/A",
                cvss_severity=f.get("cvss_severity") or "N/A",
                description=(f.get("description") or "No description available.")[:500],
            )
            text = provider.generate(prompt)
            narration = _parse_narration(text)
            # fall back to description when LLM returns unparseable text
            enriched["narration_en"] = narration["en"] or f.get("description") or ""
            enriched["narration_sw"] = narration["sw"]
            enriched["fix_en"] = narration["fix_en"]
            enriched["fix_sw"] = narration["fix_sw"]
        except Exception as exc:
            logger.warning("Narration failed for %s: %s", f["cve_id"], exc)
            enriched["narration_en"] = f.get("description") or ""
            enriched["narration_sw"] = ""
            enriched["fix_en"] = ""
            enriched["fix_sw"] = ""
        result.append(enriched)
    return result
