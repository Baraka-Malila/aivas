"""Parse TLS-related NSE script output from nmap service dicts into misconfigs.

Pure function — no I/O, no async. Reads nse_results already collected by
parse_nmap_xml() and returns misconfig dicts in the schema used by prober/headers.py.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

_AFTER_RE = re.compile(
    r"Not valid after\s*:?\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)
_BROKEN_CIPHERS = ("RC4", "export", " DES", " NULL")
_TLS_HTTPS_PORTS = frozenset({443, 8443})


def parse_tls_misconfigs(services: list[dict]) -> list[dict]:
    """Return misconfig dicts for TLS issues found in NSE output of each service."""
    findings: list[dict] = []
    for svc in services:
        nse = svc.get("nse_results") or {}
        host = svc.get("host", "")
        port = svc.get("port", 0)

        enum_out = nse.get("ssl-enum-ciphers", "")
        if enum_out:
            findings.extend(_check_ciphers(enum_out, host, port))

        cert_out = nse.get("ssl-cert", "")
        if cert_out:
            findings.extend(_check_cert_expiry(cert_out, host, port))

        headers_out = nse.get("http-security-headers", "")
        if headers_out:
            findings.extend(_check_security_headers(headers_out, host, port))

    return findings


def _check_ciphers(output: str, host: str, port: int) -> list[dict]:
    has_broken = any(c in output for c in _BROKEN_CIPHERS)
    has_tls10 = "TLSv1.0" in output
    has_modern = "TLSv1.2" in output or "TLSv1.3" in output

    results = []
    if has_broken:
        results.append({
            "type": "misconfiguration",
            "title": "Broken Cipher Suite Detected",
            "severity": "CRITICAL",
            "description": (
                "The TLS configuration includes cryptographically broken ciphers "
                "(RC4, export-grade, DES, or NULL). These can be exploited to "
                "decrypt traffic."
            ),
            "recommendation": (
                "Disable all RC4, export, DES, and NULL cipher suites in your "
                "TLS/SSL configuration. Allow only TLS 1.2+ with AEAD ciphers."
            ),
            "host": host,
            "port": port,
        })
    elif has_tls10 and not has_modern:
        results.append({
            "type": "misconfiguration",
            "title": "TLS 1.0 Only — No Modern TLS",
            "severity": "CRITICAL",
            "description": (
                "Only TLS 1.0 is enabled. TLS 1.0 is deprecated (RFC 8996) and "
                "vulnerable to BEAST and POODLE attacks. No TLS 1.2 or 1.3 detected."
            ),
            "recommendation": "Enable TLS 1.2 and TLS 1.3; disable TLS 1.0 and 1.1.",
            "host": host,
            "port": port,
        })
    elif has_tls10:
        results.append({
            "type": "misconfiguration",
            "title": "Weak TLS 1.0 Supported",
            "severity": "HIGH",
            "description": (
                "TLS 1.0 is still accepted alongside modern TLS versions. "
                "TLS 1.0 is deprecated (RFC 8996) and should be disabled."
            ),
            "recommendation": "Disable TLS 1.0 and TLS 1.1 in your server TLS configuration.",
            "host": host,
            "port": port,
        })
    return results


def _check_cert_expiry(output: str, host: str, port: int) -> list[dict]:
    m = _AFTER_RE.search(output)
    if not m:
        return []
    date_str = m.group(1)[:10]  # Take YYYY-MM-DD portion
    try:
        expiry = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return []
    now = datetime.now(timezone.utc)
    days_left = (expiry - now).days
    if days_left < 0:
        return [{
            "type": "misconfiguration",
            "title": "SSL Certificate Expired",
            "severity": "CRITICAL",
            "description": f"The SSL certificate expired on {date_str}. Clients will see security warnings.",
            "recommendation": "Renew the SSL certificate immediately.",
            "host": host,
            "port": port,
        }]
    if days_left <= 30:
        return [{
            "type": "misconfiguration",
            "title": "SSL Certificate Expiring Soon",
            "severity": "HIGH",
            "description": (
                f"The SSL certificate expires on {date_str} ({days_left} day(s) remaining). "
                "Clients will see warnings once it expires."
            ),
            "recommendation": "Renew the SSL certificate before it expires.",
            "host": host,
            "port": port,
        }]
    return []


def _check_security_headers(output: str, host: str, port: int) -> list[dict]:
    results = []
    if port in _TLS_HTTPS_PORTS and "Strict-Transport-Security" not in output:
        results.append({
            "type": "misconfiguration",
            "title": "Missing HSTS Header",
            "severity": "MEDIUM",
            "description": (
                "The Strict-Transport-Security header is absent. Without HSTS, "
                "browsers may access the site over plain HTTP, enabling downgrade attacks."
            ),
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            "host": host,
            "port": port,
        })
    if "X-Content-Type-Options" not in output:
        results.append({
            "type": "misconfiguration",
            "title": "Missing X-Content-Type-Options",
            "severity": "LOW",
            "description": "X-Content-Type-Options: nosniff is absent, allowing MIME-type sniffing.",
            "recommendation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
            "host": host,
            "port": port,
        })
    return results
