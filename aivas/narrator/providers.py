import requests
from groq import Groq


class GroqProvider:
    def __init__(self, api_key: str, model: str = "llama3-8b-8192"):
        self._client = Groq(api_key=api_key)
        self._model = model

    def generate(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
        )
        return resp.choices[0].message.content


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
