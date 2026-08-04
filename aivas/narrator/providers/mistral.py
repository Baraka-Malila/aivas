"""Mistral AI provider — uses OpenAI-compatible REST API via httpx."""
from __future__ import annotations
import json
import httpx
from .base import BaseProvider

_BASE = "https://api.mistral.ai/v1"


class MistralProvider(BaseProvider):
    def __init__(self, api_key: str, model: str = "mistral-small-latest"):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "mistral"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        resp = httpx.post(
            f"{_BASE}/chat/completions",
            headers=self._headers(),
            json={"model": self._model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"] or ""

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                async with client.stream(
                    "POST",
                    f"{_BASE}/chat/completions",
                    headers=self._headers(),
                    json={"model": self._model, "messages": messages, "max_tokens": max_tokens, "stream": True},
                ) as resp:
                    if resp.status_code == 429:
                        yield "\n\n*Rate limit reached — please wait a moment and try again.*"
                        return
                    if resp.status_code == 401:
                        yield "\n\n*Mistral API key invalid or expired — update it in Settings → AI Provider.*"
                        return
                    if resp.status_code >= 400:
                        yield f"\n\n*Mistral API error ({resp.status_code}) — please try again.*"
                        return
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        payload = line[6:]
                        if payload.strip() == "[DONE]":
                            break
                        try:
                            delta = json.loads(payload)["choices"][0]["delta"].get("content") or ""
                            if delta:
                                yield delta
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
        except httpx.TimeoutException:
            yield "\n\n*Mistral request timed out — please try again.*"
        except httpx.ConnectError:
            yield "\n\n*Cannot reach Mistral — check your network connection.*"
        except Exception as exc:
            yield f"\n\n*Unexpected error: {type(exc).__name__}. Please try again.*"
