from unittest.mock import patch, MagicMock
from http.client import HTTPMessage

import pytest

from aivas.prober.headers import check_headers
from aivas.prober.endpoints import check_endpoints
from aivas.prober.methods import check_methods
from aivas.prober import probe_http_service


def _make_response(status=200, headers_dict=None):
    """Build a mock urllib response."""
    msg = HTTPMessage()
    for k, v in (headers_dict or {}).items():
        msg[k] = v
    resp = MagicMock()
    resp.status = status
    resp.headers = msg
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# --- headers ---

def test_missing_security_headers_flagged():
    resp = _make_response(200, {"Server": "Apache/2.4.52"})
    with patch("aivas.prober.headers.urllib.request.urlopen", return_value=resp):
        result = check_headers("http://test:80")
    assert result["status"] == "ok"
    titles = [f["title"] for f in result["findings"]]
    assert "Missing X-Frame-Options" in titles
    assert "Missing Content-Security-Policy" in titles
    assert "Server version disclosure" in titles


def test_present_headers_not_flagged():
    resp = _make_response(200, {
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Server": "Apache",
    })
    with patch("aivas.prober.headers.urllib.request.urlopen", return_value=resp):
        result = check_headers("http://test:80")
    assert result["status"] == "ok"
    titles = [f["title"] for f in result["findings"]]
    assert "Missing X-Frame-Options" not in titles
    assert "Server version disclosure" not in titles


def test_etag_inode_leak_detected():
    resp = _make_response(200, {
        "ETag": '"abc123-def456-789abc"',
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
    })
    with patch("aivas.prober.headers.urllib.request.urlopen", return_value=resp):
        result = check_headers("http://test:80")
    assert result["status"] == "ok"
    titles = [f["title"] for f in result["findings"]]
    assert "ETag header leaks inode" in titles


def test_headers_returns_unreachable_on_connection_error():
    import urllib.error
    with patch("aivas.prober.headers.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        result = check_headers("http://test:80")
    assert result["status"] == "unreachable"
    assert result["findings"] == []


# --- endpoints ---

def test_server_status_found():
    resp = _make_response(200)
    import urllib.error
    def fake_urlopen(req, timeout=None):
        if "/server-status" in req.full_url:
            return resp
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch("aivas.prober.endpoints.urllib.request.urlopen", side_effect=fake_urlopen):
        result = check_endpoints("http://test:80")
    assert result["status"] == "ok"
    assert any(f["title"] == "Apache mod_status exposed" for f in result["findings"])


def test_all_endpoints_404_returns_empty():
    import urllib.error
    def raise_404(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch("aivas.prober.endpoints.urllib.request.urlopen", side_effect=raise_404):
        result = check_endpoints("http://test:80")
    assert result["status"] == "ok"
    assert result["findings"] == []


# --- methods ---

def test_trace_method_flagged():
    resp = _make_response(200, {"Allow": "GET, POST, HEAD, TRACE, OPTIONS"})
    with patch("aivas.prober.methods.urllib.request.urlopen", return_value=resp):
        result = check_methods("http://test:80")
    assert result["status"] == "ok"
    assert any("TRACE" in f["title"] for f in result["findings"])


def test_safe_methods_not_flagged():
    resp = _make_response(200, {"Allow": "GET, POST, HEAD, OPTIONS"})
    with patch("aivas.prober.methods.urllib.request.urlopen", return_value=resp):
        result = check_methods("http://test:80")
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_methods_returns_unreachable_on_error():
    import urllib.error
    with patch("aivas.prober.methods.urllib.request.urlopen",
               side_effect=urllib.error.URLError("timeout")):
        result = check_methods("http://test:80")
    assert result["status"] == "unreachable"
    assert result["findings"] == []


# --- integration ---

def test_probe_http_service_aggregates():
    with patch("aivas.prober.headers.urllib.request.urlopen",
               return_value=_make_response(200, {"Server": "Apache/2.4.52"})), \
         patch("aivas.prober.endpoints.urllib.request.urlopen",
               side_effect=Exception("not found")), \
         patch("aivas.prober.methods.urllib.request.urlopen",
               return_value=_make_response(200, {"Allow": "GET, POST, TRACE"})):
        result = probe_http_service("192.168.1.1", 80, scheme="http")
    assert result["status"] in ("ok", "error")
    assert len(result["findings"]) > 0
    types = {f["type"] for f in result["findings"]}
    assert types == {"misconfiguration"}


def test_probe_http_service_unreachable_when_all_unreachable():
    import urllib.error
    with patch("aivas.prober.headers.urllib.request.urlopen",
               side_effect=urllib.error.URLError("refused")), \
         patch("aivas.prober.endpoints.urllib.request.urlopen",
               side_effect=urllib.error.URLError("refused")), \
         patch("aivas.prober.methods.urllib.request.urlopen",
               side_effect=urllib.error.URLError("refused")):
        result = probe_http_service("192.168.1.1", 9999, scheme="http")
    assert result["status"] == "unreachable"
    assert result["findings"] == []
