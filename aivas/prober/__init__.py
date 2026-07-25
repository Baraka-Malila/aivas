from .headers import check_headers
from .endpoints import check_endpoints
from .methods import check_methods


def probe_http_service(host: str, port: int, scheme: str = "http") -> dict:
    """Run all Level 1 config probes against an HTTP service.

    Returns {"status": "ok"|"unreachable"|"error", "findings": list[dict]}.
    """
    url = f"{scheme}://{host}:{port}"
    h = check_headers(url)
    e = check_endpoints(url)
    m = check_methods(url)
    statuses = {h["status"], e["status"], m["status"]}
    if statuses == {"unreachable"}:
        status = "unreachable"
    elif "ok" in statuses:
        status = "ok"
    else:
        status = "error"
    findings = h["findings"] + e["findings"] + m["findings"]
    return {"status": status, "findings": findings}


__all__ = [
    "probe_http_service",
    "check_headers",
    "check_endpoints",
    "check_methods",
]
