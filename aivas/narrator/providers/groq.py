import re
import time
from groq import Groq, AsyncGroq
from .base import BaseProvider

_RETRY_DELAYS = (2.0, 6.0)


class GroqProvider(BaseProvider):
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self._api_key = api_key
        self._client = Groq(api_key=api_key)
        self._model = model

    @property
    def name(self) -> str:
        return "groq"

    @staticmethod
    def _retry_delay(error: Exception) -> float | None:
        m = re.search(r"try again in ([\d.]+)s", str(error), re.IGNORECASE)
        return float(m.group(1)) if m else None

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        for _attempt, backoff in enumerate(_RETRY_DELAYS + (None,)):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                )
                return resp.choices[0].message.content
            except Exception as exc:
                is_rate = "429" in str(exc) or "rate_limit" in str(exc).lower()
                if is_rate and backoff is not None:
                    time.sleep(self._retry_delay(exc) or backoff)
                    continue
                raise

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        client = AsyncGroq(api_key=self._api_key)
        try:
            resp = await client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=max_tokens,
                stream=True,
            )
            async for chunk in resp:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            s = str(exc)
            if "429" in s or "rate_limit" in s.lower():
                yield "\n\n*Rate limit reached — please wait a moment and try again.*"
            else:
                raise
