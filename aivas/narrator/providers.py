import re
import time
import requests
from groq import Groq

_RETRY_DELAYS = (2.0, 6.0)


class GroqProvider:
    def __init__(self, api_key: str, model: str = "llama-3.1-8b-instant"):
        self._client = Groq(api_key=api_key)
        self._model = model

    @staticmethod
    def _retry_delay(error: Exception) -> float | None:
        m = re.search(r"try again in ([\d.]+)s", str(error), re.IGNORECASE)
        return float(m.group(1)) if m else None

    def generate(self, prompt: str) -> str:
        for attempt, backoff in enumerate(_RETRY_DELAYS + (None,)):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=300,
                )
                return resp.choices[0].message.content
            except Exception as exc:
                is_rate_limit = "429" in str(exc) or "rate_limit" in str(exc).lower()
                if is_rate_limit and backoff is not None:
                    delay = self._retry_delay(exc) or backoff
                    time.sleep(delay)
                    continue
                raise


class OllamaProvider:
    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self._model = model
        self._base_url = base_url.rstrip("/")

    def generate(self, prompt: str) -> str:
        resp = requests.post(
            f"{self._base_url}/api/generate",
            json={"model": self._model, "prompt": prompt, "stream": False},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["response"]


def get_provider(name: str, api_key: str | None = None) -> GroqProvider | OllamaProvider:
    if name == "groq":
        if not api_key:
            raise ValueError(
                "Groq API key required. Set GROQ_API_KEY env var or pass --api-key."
            )
        return GroqProvider(api_key=api_key)
    if name == "ollama":
        return OllamaProvider()
    raise ValueError(f"Unknown provider: {name!r}. Choose 'groq' or 'ollama'.")
