"""Parse natural language scan queries into structured scan intent via LLM."""

import json
from typing import Protocol

INTENT_PROMPT = """\
You are a network security assistant. Extract scan intent from this query.
Return ONLY valid JSON with these keys:
- "target": IP address, hostname, or CIDR range (required)
- "level": scan depth 1 (quick), 2 (full, default), or 3 (deep)
- "focus": brief description of what the user wants to find (optional, null if unclear)

Query: {query}

JSON:"""


class LLMProvider(Protocol):
    def generate(self, prompt: str) -> str: ...


def parse_intent(query: str, provider: LLMProvider) -> dict:
    """Parse a natural language query into a structured scan intent dict.

    Returns a dict with keys: target (str), level (int 1-3), focus (str | None).
    Raises ValueError if the LLM response contains no JSON or lacks a target.
    """
    prompt = INTENT_PROMPT.format(query=query)
    text = provider.generate(prompt)

    start = text.find("{")
    end = text.rfind("}") + 1
    if start < 0 or end <= start:
        raise ValueError(f"No JSON found in LLM response: {text!r}")

    try:
        data = json.loads(text[start:end])
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in LLM response: {exc}") from exc

    if "target" not in data or not data["target"]:
        raise ValueError("LLM response missing required 'target' key.")

    return {
        "target": str(data["target"]),
        "level": int(data.get("level") or 2),
        "focus": data.get("focus") or None,
    }
