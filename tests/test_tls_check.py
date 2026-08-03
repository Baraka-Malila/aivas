"""Tests for TLS NSE output parsing."""
from aivas.scanner.tls_check import parse_tls_misconfigs
from datetime import datetime, timezone, timedelta


def _svc(nse: dict, host: str = "10.0.0.1", port: int = 443) -> dict:
    return {"host": host, "port": port, "protocol": "tcp", "nse_results": nse}


# --- ssl-enum-ciphers tests ---

def test_tls10_with_modern_is_high():
    nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:\nTLSv1.2:\n  ciphers:"}
    result = parse_tls_misconfigs([_svc(nse)])
    sevs = [r["severity"] for r in result]
    assert "HIGH" in sevs
    assert "CRITICAL" not in sevs


def test_tls10_only_is_critical():
    nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:"}
    result = parse_tls_misconfigs([_svc(nse)])
    sevs = [r["severity"] for r in result]
    assert "CRITICAL" in sevs


def test_broken_cipher_rc4_is_critical():
    nse = {"ssl-enum-ciphers": "TLSv1.2:\n  TLS_RSA_WITH_RC4_128_SHA"}
    result = parse_tls_misconfigs([_svc(nse)])
    assert any(r["severity"] == "CRITICAL" for r in result)


def test_no_cipher_issues_returns_empty():
    nse = {"ssl-enum-ciphers": "TLSv1.2:\n  ciphers:\nTLSv1.3:\n  ciphers:"}
    result = parse_tls_misconfigs([_svc(nse)])
    assert result == []


# --- ssl-cert expiry tests ---

def test_expired_cert_is_critical():
    past = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
    nse = {"ssl-cert": f"Subject: commonName=example.com\nNot valid after:  {past}"}
    result = parse_tls_misconfigs([_svc(nse)])
    assert any(r["severity"] == "CRITICAL" and "Expired" in r["title"] for r in result)


def test_expiring_soon_cert_is_high():
    soon = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%S")
    nse = {"ssl-cert": f"Not valid after:  {soon}"}
    result = parse_tls_misconfigs([_svc(nse)])
    assert any(r["severity"] == "HIGH" and "Expiring" in r["title"] for r in result)


def test_valid_cert_returns_empty():
    future = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
    nse = {"ssl-cert": f"Not valid after:  {future}"}
    result = parse_tls_misconfigs([_svc(nse)])
    assert result == []


# --- http-security-headers tests ---

def test_missing_hsts_on_443_is_medium():
    nse = {"http-security-headers": "X-Frame-Options: SAMEORIGIN\nX-Content-Type-Options: nosniff"}
    result = parse_tls_misconfigs([_svc(nse, port=443)])
    assert any(r["severity"] == "MEDIUM" and "HSTS" in r["title"] for r in result)


def test_hsts_present_no_medium():
    nse = {"http-security-headers": "Strict-Transport-Security: max-age=31536000"}
    result = parse_tls_misconfigs([_svc(nse, port=443)])
    assert not any("HSTS" in r.get("title", "") for r in result)


def test_non_tls_port_no_hsts_check():
    nse = {"http-security-headers": "X-Frame-Options: SAMEORIGIN"}
    result = parse_tls_misconfigs([_svc(nse, port=80)])
    assert not any("HSTS" in r.get("title", "") for r in result)


def test_no_nse_results_returns_empty():
    result = parse_tls_misconfigs([_svc({})])
    assert result == []


def test_host_and_port_in_output():
    nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:"}
    result = parse_tls_misconfigs([_svc(nse, host="192.168.1.5", port=8443)])
    assert result[0]["host"] == "192.168.1.5"
    assert result[0]["port"] == 8443
