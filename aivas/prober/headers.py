import re
import urllib.request
import urllib.error


_SECURITY_HEADERS = [
    ("X-Frame-Options", "MEDIUM",
     "Missing X-Frame-Options header allows clickjacking attacks.",
     "Add 'X-Frame-Options: SAMEORIGIN' to server configuration."),
    ("X-Content-Type-Options", "LOW",
     "Missing X-Content-Type-Options allows MIME-type sniffing.",
     "Add 'X-Content-Type-Options: nosniff' to server configuration."),
    ("Content-Security-Policy", "MEDIUM",
     "Missing Content-Security-Policy header increases XSS risk.",
     "Define a Content-Security-Policy header appropriate for your application."),
]

_ETAG_INODE_RE = re.compile(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"', re.IGNORECASE)
_SERVER_VERSION_RE = re.compile(r'(apache|nginx|iis|lighttpd|openssl)[/\s]([\d.]+)',
                                 re.IGNORECASE)


def check_headers(url: str, timeout: int = 5) -> list[dict]:
    """Return misconfiguration findings from HTTP response headers."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return []

    findings = []

    for header_name, severity, description, recommendation in _SECURITY_HEADERS:
        if header_name.lower() not in headers:
            findings.append({
                "type": "misconfiguration",
                "title": f"Missing {header_name}",
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            })

    server_val = headers.get("server", "")
    if _SERVER_VERSION_RE.search(server_val):
        findings.append({
            "type": "misconfiguration",
            "title": "Server version disclosure",
            "severity": "LOW",
            "description": (
                f"Server header reveals software version: '{server_val}'. "
                "Attackers can target known vulnerabilities for this version."
            ),
            "recommendation": (
                "Configure ServerTokens Prod (Apache) or server_tokens off "
                "(nginx) to suppress version information."
            ),
        })

    etag_val = headers.get("etag", "")
    if _ETAG_INODE_RE.match(etag_val):
        findings.append({
            "type": "misconfiguration",
            "title": "ETag header leaks inode",
            "severity": "LOW",
            "description": (
                f"ETag value '{etag_val}' follows the Apache inode-size-mtime "
                "pattern, disclosing internal filesystem information."
            ),
            "recommendation": (
                "Disable ETag or configure 'FileETag MTime Size' in Apache "
                "to exclude inode from the hash."
            ),
        })

    return findings
