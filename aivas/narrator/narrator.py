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
{{"en": "English narration here.", "sw": "Maelezo ya Kiswahili hapa."}}"""


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
                return {"en": str(data["en"]), "sw": str(data["sw"])}
        except json.JSONDecodeError:
            pass
    return {"en": "", "sw": ""}


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
        except Exception as exc:
            logger.warning("Narration failed for %s: %s", f["cve_id"], exc)
            enriched["narration_en"] = f.get("description") or ""
            enriched["narration_sw"] = ""
        result.append(enriched)
    return result
