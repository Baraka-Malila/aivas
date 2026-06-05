import urllib.request
import urllib.error


_SENSITIVE_PATHS = [
    ("/server-status", "Apache mod_status exposed",
     "HIGH",
     "/server-status reveals real-time request traffic, IP addresses, and "
     "worker state. Accessible without authentication.",
     "Restrict /server-status to localhost: "
     "'Require ip 127.0.0.1' in Apache config."),
    ("/server-info", "Apache mod_info exposed",
     "HIGH",
     "/server-info discloses Apache configuration, loaded modules, and "
     "build settings.",
     "Restrict /server-info to localhost or disable mod_info entirely."),
    ("/.git/HEAD", "Git repository exposed",
     "HIGH",
     "The .git directory is publicly accessible. Attackers can reconstruct "
     "source code and extract secrets from git history.",
     "Deny access to /.git/ in web server config or move the repo outside "
     "the document root."),
    ("/.env", ".env file exposed",
     "HIGH",
     ".env file is accessible — may contain database credentials, API keys, "
     "and other secrets.",
     "Deny access to .env files in web server config."),
    ("/wp-admin/", "WordPress admin panel exposed",
     "MEDIUM",
     "/wp-admin/ is publicly reachable. WordPress admin panels are a common "
     "target for brute-force and credential-stuffing attacks.",
     "Restrict /wp-admin/ by IP or implement rate limiting and 2FA."),
    ("/phpmyadmin/", "phpMyAdmin exposed",
     "HIGH",
     "phpMyAdmin database manager is publicly accessible. "
     "Known target for automated exploit attempts.",
     "Move phpMyAdmin to a non-standard path and restrict by IP."),
]


def check_endpoints(url: str, timeout: int = 5) -> list[dict]:
    """Return misconfiguration findings for exposed sensitive paths."""
    findings = []
    for path, title, severity, description, recommendation in _SENSITIVE_PATHS:
        full_url = url.rstrip("/") + path
        try:
            req = urllib.request.Request(full_url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "type": "misconfiguration",
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "recommendation": recommendation,
                    })
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403, 404):
                pass
        except Exception:
            pass
    return findings
