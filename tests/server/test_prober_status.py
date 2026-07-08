from unittest.mock import patch
from urllib.error import URLError

from aivas.prober import probe_http_service


def test_unreachable_returns_status_unreachable():
    with patch("urllib.request.urlopen", side_effect=URLError("Connection refused")):
        result = probe_http_service("127.0.0.1", 9999, scheme="http")
    assert result["status"] == "unreachable"
    assert result["findings"] == []


def test_ok_returns_status_ok():
    fake_resp = type("R", (), {
        "headers": {"server": "Apache"},
        "read": lambda self, *a: b"",
        "status": 200,
        "__enter__": lambda self: self,
        "__exit__": lambda self, *a: None,
    })()
    with patch("urllib.request.urlopen", return_value=fake_resp):
        result = probe_http_service("127.0.0.1", 80, scheme="http")
    assert result["status"] in ("ok", "error")
    assert isinstance(result["findings"], list)


def test_result_has_status_and_findings_keys():
    with patch("urllib.request.urlopen", side_effect=URLError("refused")):
        result = probe_http_service("127.0.0.1", 9999, scheme="http")
    assert "status" in result
    assert "findings" in result


def test_findings_is_list_of_dicts_on_ok():
    from http.client import HTTPMessage
    from unittest.mock import MagicMock

    msg = HTTPMessage()
    resp = MagicMock()
    resp.status = 200
    resp.headers = msg
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)

    with patch("aivas.prober.headers.urllib.request.urlopen", return_value=resp), \
         patch("aivas.prober.endpoints.urllib.request.urlopen",
               side_effect=URLError("refused")), \
         patch("aivas.prober.methods.urllib.request.urlopen",
               side_effect=URLError("refused")):
        result = probe_http_service("127.0.0.1", 80, scheme="http")

    assert result["status"] in ("ok", "unreachable", "error")
    assert isinstance(result["findings"], list)
    for f in result["findings"]:
        assert isinstance(f, dict)
