import urllib.request
import urllib.error


_RISKY_METHODS = {
    "TRACE": ("HTTP TRACE method enabled",
              "HIGH",
              "TRACE method enables Cross-Site Tracing (XST) attacks, "
              "potentially allowing theft of HTTP-only cookies.",
              "Disable TRACE method: 'TraceEnable off' in Apache config."),
    "DELETE": ("HTTP DELETE method enabled",
               "MEDIUM",
               "DELETE method is enabled. If not properly restricted, "
               "attackers may delete files on the server.",
               "Restrict DELETE to authenticated APIs only, or disable."),
    "PUT": ("HTTP PUT method enabled",
            "MEDIUM",
            "PUT method is enabled. Unrestricted PUT may allow arbitrary "
            "file upload to the server.",
            "Restrict PUT to authenticated endpoints only, or disable."),
}


def check_methods(url: str, timeout: int = 5) -> list[dict]:
    """Return misconfiguration findings for dangerous HTTP methods."""
    findings = []
    try:
        req = urllib.request.Request(url, method="OPTIONS")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            allow = resp.headers.get("Allow", "")
    except urllib.error.HTTPError as e:
        allow = e.headers.get("Allow", "") if e.headers else ""
    except Exception:
        return []

    allowed_methods = {m.strip().upper() for m in allow.split(",")}
    for method, (title, severity, description, recommendation) in _RISKY_METHODS.items():
        if method in allowed_methods:
            findings.append({
                "type": "misconfiguration",
                "title": title,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            })
    return findings
