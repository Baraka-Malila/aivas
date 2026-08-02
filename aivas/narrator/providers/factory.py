from .base import BaseProvider

_DEFAULTS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "claude": "claude-haiku-4-5-20251001",
    "ollama": "llama3",
}


def get_provider(
    name: str,
    model: str | None = None,
    api_key: str | None = None,
) -> BaseProvider:
    m = model or _DEFAULTS.get(name)
    if name == "groq":
        if not api_key:
            raise ValueError(
                "Groq API key required. Set GROQ_API_KEY env var or pass api_key."
            )
        from .groq import GroqProvider
        return GroqProvider(api_key=api_key, model=m)
    if name == "claude":
        if not api_key:
            raise ValueError("Anthropic API key required for claude provider.")
        from .anthropic import AnthropicProvider
        return AnthropicProvider(api_key=api_key, model=m)
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(model=m)
    raise ValueError(f"Unknown provider: {name!r}. Choose 'groq', 'claude', or 'ollama'.")
