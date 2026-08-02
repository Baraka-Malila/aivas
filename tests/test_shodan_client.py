from unittest.mock import patch, MagicMock
from aivas.narrator.shodan_client import query_shodan


def test_query_shodan_returns_dict():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "ip_str": "1.1.1.1",
        "ports": [80, 443],
        "hostnames": ["one.one.one.one"],
        "country_name": "Australia",
        "org": "Cloudflare",
        "vulns": {},
        "tags": ["cdn"],
    }
    with patch("aivas.narrator.shodan_client.requests.get", return_value=mock_resp):
        result = query_shodan("1.1.1.1", "fake-key")
    assert result["ip"] == "1.1.1.1"
    assert result["ports"] == [80, 443]
    assert result["org"] == "Cloudflare"


def test_query_shodan_empty_key_returns_error():
    result = query_shodan("1.1.1.1", "")
    assert "error" in result
    assert "not configured" in result["error"]


def test_query_shodan_http_error_returns_error():
    import requests as _requests
    with patch("aivas.narrator.shodan_client.requests.get", side_effect=_requests.HTTPError("403 Forbidden")):
        result = query_shodan("1.1.1.1", "fake-key")
    assert "error" in result
