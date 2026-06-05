from unittest.mock import patch, MagicMock
from aivas.scanner.probe import probe_http, probe_banner, probe_ssl


def test_probe_http_returns_server_header():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "nginx/1.18.0"}
    mock_resp.text = "<html><title>Hello</title></html>"
    with patch("aivas.scanner.probe.requests.get", return_value=mock_resp):
        result = probe_http("192.168.1.1", 80)
    assert result["server"] == "nginx/1.18.0"
    assert result["status"] == 200
    assert result["title"] == "Hello"


def test_probe_http_returns_empty_on_error():
    with patch("aivas.scanner.probe.requests.get", side_effect=Exception("refused")):
        result = probe_http("192.168.1.1", 9999)
    assert result == {"status": 0, "server": "", "title": ""}


def test_probe_banner_returns_banner():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
    with patch("aivas.scanner.probe.socket.create_connection", return_value=mock_sock):
        result = probe_banner("192.168.1.1", 22)
    assert "SSH" in result


def test_probe_banner_returns_empty_on_timeout():
    with patch("aivas.scanner.probe.socket.create_connection", side_effect=OSError("timeout")):
        result = probe_banner("192.168.1.1", 9999)
    assert result == ""


def test_probe_ssl_returns_cn():
    mock_result = MagicMock()
    mock_result.stdout = b"subject=CN=example.com, O=Example Corp\n"
    mock_result.stderr = b""
    with patch("aivas.scanner.probe.subprocess.run", return_value=mock_result):
        result = probe_ssl("192.168.1.1", 443)
    assert result["cn"] == "example.com"


def test_probe_ssl_returns_empty_on_error():
    with patch("aivas.scanner.probe.subprocess.run", side_effect=Exception("no openssl")):
        result = probe_ssl("192.168.1.1", 443)
    assert result == {"cn": "", "raw": ""}
