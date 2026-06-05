from unittest.mock import patch, MagicMock
import pytest
import requests
from aivas.narrator.providers import GroqProvider, OllamaProvider, get_provider


def test_get_provider_groq_raises_without_key():
    with pytest.raises(ValueError, match="Groq API key"):
        get_provider("groq", api_key=None)


def test_get_provider_groq_returns_groq_provider():
    with patch("aivas.narrator.providers.Groq"):
        p = get_provider("groq", api_key="fake-key")
    assert isinstance(p, GroqProvider)


def test_get_provider_ollama_returns_ollama_provider():
    p = get_provider("ollama")
    assert isinstance(p, OllamaProvider)


def test_get_provider_unknown_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("openai")


def test_groq_provider_generate_returns_string():
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = '{"en": "test", "sw": "jaribio"}'
    with patch("aivas.narrator.providers.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = mock_resp
        p = GroqProvider(api_key="fake-key")
        result = p.generate("prompt text")
    assert result == '{"en": "test", "sw": "jaribio"}'


def test_ollama_provider_generate_posts_to_api():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"response": "Ollama output"}
        )
        p = OllamaProvider()
        result = p.generate("prompt text")
    assert result == "Ollama output"
    called_url = mock_post.call_args[0][0]
    assert "11434" in called_url
    assert "generate" in called_url


def test_ollama_provider_raises_on_http_error():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=404,
            raise_for_status=MagicMock(side_effect=requests.HTTPError("404"))
        )
        p = OllamaProvider()
        with pytest.raises(requests.HTTPError):
            p.generate("prompt text")
