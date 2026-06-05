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
        findings = check_headers("http://test:80")
    titles = [f["title"] for f in findings]
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
        findings = check_headers("http://test:80")
    titles = [f["title"] for f in findings]
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
        findings = check_headers("http://test:80")
    titles = [f["title"] for f in findings]
    assert "ETag header leaks inode" in titles


def test_headers_returns_empty_on_connection_error():
    with patch("aivas.prober.headers.urllib.request.urlopen",
               side_effect=Exception("connection refused")):
        findings = check_headers("http://test:80")
    assert findings == []


# --- endpoints ---

def test_server_status_found():
    resp = _make_response(200)
    import urllib.error
    def fake_urlopen(req, timeout=None):
        if "/server-status" in req.full_url:
            return resp
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch("aivas.prober.endpoints.urllib.request.urlopen", side_effect=fake_urlopen):
        findings = check_endpoints("http://test:80")
    assert any(f["title"] == "Apache mod_status exposed" for f in findings)


def test_all_endpoints_404_returns_empty():
    import urllib.error
    def raise_404(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch("aivas.prober.endpoints.urllib.request.urlopen", side_effect=raise_404):
        findings = check_endpoints("http://test:80")
    assert findings == []


# --- methods ---

def test_trace_method_flagged():
    resp = _make_response(200, {"Allow": "GET, POST, HEAD, TRACE, OPTIONS"})
    with patch("aivas.prober.methods.urllib.request.urlopen", return_value=resp):
        findings = check_methods("http://test:80")
    assert any("TRACE" in f["title"] for f in findings)


def test_safe_methods_not_flagged():
    resp = _make_response(200, {"Allow": "GET, POST, HEAD, OPTIONS"})
    with patch("aivas.prober.methods.urllib.request.urlopen", return_value=resp):
        findings = check_methods("http://test:80")
    assert findings == []


def test_methods_returns_empty_on_error():
    with patch("aivas.prober.methods.urllib.request.urlopen",
               side_effect=Exception("timeout")):
        findings = check_methods("http://test:80")
    assert findings == []


# --- integration ---

def test_probe_http_service_aggregates():
    with patch("aivas.prober.headers.urllib.request.urlopen",
               return_value=_make_response(200, {"Server": "Apache/2.4.52"})), \
         patch("aivas.prober.endpoints.urllib.request.urlopen",
               side_effect=Exception("not found")), \
         patch("aivas.prober.methods.urllib.request.urlopen",
               return_value=_make_response(200, {"Allow": "GET, POST, TRACE"})):
        findings = probe_http_service("192.168.1.1", 80, ssl=False)
    assert len(findings) > 0
    types = {f["type"] for f in findings}
    assert types == {"misconfiguration"}
