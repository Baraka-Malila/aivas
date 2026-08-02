import asyncio
import json
import requests
from .base import BaseProvider


class OllamaProvider(BaseProvider):
    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self._model = model
        self._base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        resp = requests.post(
            f"{self._base_url}/api/generate",
            json={
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["response"]

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        chat_msgs = [
            m for m in messages if m.get("role") in ("user", "assistant", "system")
        ]

        def _run():
            try:
                resp = requests.post(
                    f"{self._base_url}/api/chat",
                    json={
                        "model": self._model,
                        "messages": chat_msgs,
                        "stream": True,
                        "options": {"num_predict": max_tokens},
                    },
                    stream=True,
                    timeout=120,
                )
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line:
                        data = json.loads(line)
                        token = data.get("message", {}).get("content", "")
                        if token:
                            loop.call_soon_threadsafe(queue.put_nowait, token)
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, f"\n[Ollama error: {exc}]")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        thread = loop.run_in_executor(None, _run)
        while True:
            token = await queue.get()
            if token is None:
                break
            yield token
        await thread
