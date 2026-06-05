from .headers import check_headers
from .endpoints import check_endpoints
from .methods import check_methods


def probe_http_service(host: str, port: int, ssl: bool = False) -> list[dict]:
    """Run all Level 1 config probes against an HTTP service."""
    scheme = "https" if ssl else "http"
    url = f"{scheme}://{host}:{port}"
    findings: list[dict] = []
    findings.extend(check_headers(url))
    findings.extend(check_endpoints(url))
    findings.extend(check_methods(url))
    return findings


__all__ = [
    "probe_http_service",
    "check_headers",
    "check_endpoints",
    "check_methods",
]
