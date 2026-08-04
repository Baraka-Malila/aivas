from .base import BaseProvider

_DEFAULTS: dict[str, str] = {
    "groq":    "llama-3.3-70b-versatile",
    "mistral": "mistral-small-latest",
    "ollama":  "llama3",
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
    if name == "mistral":
        if not api_key:
            raise ValueError("Mistral API key required. Set MISTRAL_API_KEY env var or pass api_key.")
        from .mistral import MistralProvider
        return MistralProvider(api_key=api_key, model=m)
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(model=m)
    raise ValueError(f"Unknown provider: {name!r}. Choose 'groq', 'mistral', or 'ollama'.")
