from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import pytest
import requests
from aivas.narrator.providers import GroqProvider, OllamaProvider, get_provider
from aivas.narrator.providers.base import BaseProvider


# --- factory ---

def test_get_provider_groq_raises_without_key():
    with pytest.raises(ValueError, match="Groq API key"):
        get_provider("groq", api_key=None)

def test_get_provider_groq_returns_groq_provider():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="fake-key")
    assert isinstance(p, GroqProvider)

def test_get_provider_groq_default_model():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="k")
    assert p._model == "llama-3.3-70b-versatile"

def test_get_provider_groq_custom_model():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="k", model="llama-3.1-8b-instant")
    assert p._model == "llama-3.1-8b-instant"

def test_get_provider_ollama_returns_ollama_provider():
    p = get_provider("ollama")
    assert isinstance(p, OllamaProvider)

def test_get_provider_claude_raises_without_key():
    with pytest.raises(ValueError, match="Anthropic"):
        get_provider("claude", api_key=None)

def test_get_provider_unknown_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("openai")

# --- GroqProvider ---

def test_groq_generate_returns_string():
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "response text"
    with patch("aivas.narrator.providers.groq.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = mock_resp
        p = GroqProvider(api_key="fake-key")
        result = p.generate("prompt")
    assert result == "response text"

def test_groq_name():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = GroqProvider(api_key="k")
    assert p.name == "groq"

def test_groq_stream_yields_tokens():
    async def _run():
        async def mock_aiter(self):
            for content in ["Hello", " World"]:
                chunk = MagicMock()
                chunk.choices[0].delta.content = content
                yield chunk

        mock_stream = MagicMock()
        mock_stream.__aiter__ = mock_aiter

        with patch("aivas.narrator.providers.groq.AsyncGroq") as MockAsync:
            MockAsync.return_value.chat.completions.create = AsyncMock(
                return_value=mock_stream
            )
            from aivas.narrator.providers.groq import GroqProvider
            p = GroqProvider(api_key="k")
            tokens = [t async for t in p.stream([{"role": "user", "content": "hi"}])]
        return tokens

    tokens = asyncio.run(_run())
    assert tokens == ["Hello", " World"]

# --- OllamaProvider ---

def test_ollama_generate_posts_to_api():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"response": "Ollama output"}
        )
        mock_post.return_value.raise_for_status = MagicMock()
        p = OllamaProvider()
        result = p.generate("prompt text")
    assert result == "Ollama output"
    assert "11434" in mock_post.call_args[0][0]
    assert "generate" in mock_post.call_args[0][0]

def test_ollama_name():
    p = OllamaProvider()
    assert p.name == "ollama"

def test_ollama_raises_on_http_error():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            raise_for_status=MagicMock(side_effect=requests.HTTPError("404"))
        )
        p = OllamaProvider()
        with pytest.raises(requests.HTTPError):
            p.generate("prompt text")

# --- BaseProvider is abstract ---

def test_base_provider_is_abstract():
    with pytest.raises(TypeError):
        BaseProvider()
