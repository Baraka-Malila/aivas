from .base import BaseProvider


class AnthropicProvider(BaseProvider):
    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "claude"

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        from anthropic import Anthropic
        client = Anthropic(api_key=self._api_key)
        resp = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=self._api_key)
        system = next(
            (m["content"] for m in messages if m.get("role") == "system"), ""
        )
        chat_msgs = [
            m for m in messages
            if m.get("role") in ("user", "assistant") and m.get("content")
        ]
        if not chat_msgs:
            return
        async with client.messages.stream(
            model=self._model,
            max_tokens=max_tokens,
            system=system or "You are a helpful assistant.",
            messages=chat_msgs,
        ) as s:
            async for text in s.text_stream:
                yield text
