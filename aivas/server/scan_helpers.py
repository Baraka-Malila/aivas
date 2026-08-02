"""Per-host scan helpers: CVE event stream, HTTP probe events, device-type inference."""
from __future__ import annotations

import asyncio
import sqlite3
from typing import AsyncGenerator

from aivas.correlator import correlate
from aivas.parser import parse_nmap_xml

_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}

_DEVICE_PATTERNS: list[tuple[set[int], str, bool]] = [
    ({554, 37777}, "Camera", False),  # OR logic: either port triggers
    ({9100}, "Printer", False),
    ({5555}, "Android", False),
    ({3389}, "Windows", False),
    ({139, 445}, "Windows", True),   # AND logic: both ports required
]


def device_type_from_ports(ports: list[int]) -> str:
    """Infer device type from open ports."""
    port_set = set(ports)
    for pattern, label, require_all in _DEVICE_PATTERNS:
        # require_all=True: all ports in pattern must be present (AND)
        # require_all=False: any port in pattern triggers match (OR)
        if require_all:
            if pattern.issubset(port_set):
                return label
        else:
            if pattern & port_set:
                return label
    if 23 in port_set and not port_set & {22, 3389}:
        return "Router"
    if 22 in port_set:
        return "Linux"
    return "Unknown"


def _ev(phase: str, text: str, **extra) -> dict:
    """Create a progress event dict."""
    return {"type": "progress", "phase": phase, "text": text, **extra}


def _svc_label(svc: dict) -> str:
    """Format service name and version as a label."""
    return (
        f"{svc.get('product') or svc.get('service') or 'unknown'} "
        f"{svc.get('version') or ''}"
    ).strip()


async def cve_events(
    conn: sqlite3.Connection,
    services: list[dict],
    indent: str = "  ",
) -> AsyncGenerator[dict, None]:
    """Yield progress events for CVE lookup; last item is {'__findings': [...]}."""
    os_hint = services[0].get("os_family") if services else None
    all_findings: list[dict] = []
    for svc in services:
        yield _ev("cve_lookup", f"{indent}{_svc_label(svc)} (port {svc.get('port','?')})…")
        svc_findings = await asyncio.to_thread(correlate, conn, [svc], os_hint)
        await asyncio.sleep(0.05)
        probable = [f for f in svc_findings if f.get("confidence") in ("probable", "confirmed")]
        if probable:
            worst = max(probable, key=lambda f: f.get("cvss_score") or 0)
            yield _ev(
                "cve_found",
                f"{indent}→ {len(probable)} CVE(s) — worst: "
                f"{worst.get('cve_id','')} ({worst.get('cvss_severity','')} "
                f"{worst.get('cvss_score','')})",
            )
        else:
            yield _ev("cve_none", f"{indent}→ no CVEs matched")
        all_findings.extend(svc_findings)
    yield {"__findings": all_findings}


async def http_probe_events(
    services: list[dict],
) -> AsyncGenerator[dict, None]:
    """Yield HTTP probe progress events; last item is {'__misconfigs': [...]}."""
    from aivas.prober import probe_http_service

    http_svcs = [
        s for s in services
        if s.get("port") in _HTTP_PORTS
        or s.get("service") in ("http", "https", "http-alt")
    ]
    if not http_svcs:
        yield {"__misconfigs": []}
        return

    all_misconfigs: list[dict] = []
    for svc in http_svcs:
        port = svc.get("port", 80)
        host = svc.get("host", "")
        scheme = "https" if (port in (443, 8443) or svc.get("service") == "https") else "http"
        label = f"{host}:{port}"
        yield _ev("http_probe", f"  {label} — probing headers, paths, methods…")
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(probe_http_service, host, port, scheme),
                timeout=12.0,
            )
        except asyncio.TimeoutError:
            yield _ev("http_timeout", f"  {label} — HTTP probe timed out (12s), skipping")
            continue
        except Exception as exc:
            yield _ev("http_error", f"  {label} — probe error: {exc}")
            continue
        if result["status"] == "unreachable":
            yield _ev("http_unreachable",
                      f"  {label} — HTTP probe failed (host did not respond)")
            continue
        if result["status"] == "error":
            yield _ev("http_error",
                      f"  {label} — {result.get('error', 'probe error')}")
            continue
        # status == "ok"
        for f in result["findings"]:
            f["host"] = host
            f["port"] = port
            all_misconfigs.append(f)
            yield _ev("http_finding",
                      f"  {label} — {f.get('title', 'finding')} "
                      f"[{f.get('severity', 'MEDIUM')}]")
    if not all_misconfigs:
        yield _ev("http_clean", "  No HTTP misconfigurations detected")
    yield {"__misconfigs": all_misconfigs}


async def scan_host(
    conn: sqlite3.Connection, host_ip: str, scripts: str,
    nmap_fn,
) -> AsyncGenerator[dict, None]:
    """Scan one host; yield events then sentinel with __svcs/__findings/__misconfigs."""
    fut = asyncio.create_task(nmap_fn(host_ip, scripts, 120))
    start = asyncio.get_running_loop().time()
    xml: str | None = None
    try:
        while not fut.done():
            try:
                await asyncio.wait_for(asyncio.shield(fut), timeout=3.0)
            except asyncio.TimeoutError:
                elapsed = int(asyncio.get_running_loop().time() - start)
                yield _ev("scanning", f"  {host_ip}: scanning… {elapsed}s")
        try:
            xml = await fut
        except Exception as exc:
            yield {"type": "error", "text": str(exc)}
            return
    finally:
        if not fut.done():
            fut.cancel()
            try:
                await fut
            except (asyncio.CancelledError, Exception):
                pass
    try:
        services = parse_nmap_xml(xml)
    except Exception as exc:
        yield {"type": "error", "text": f"Parse error {host_ip}: {exc}"}
        return
    if not services:
        yield _ev("host_no_ports", f"  {host_ip}: no open ports found")
        yield {"__svcs": [], "__findings": [], "__misconfigs": []}
        return
    ports = [s.get("port", 0) for s in services]
    dtype = device_type_from_ports(ports)
    yield _ev("host_scan", f"── {host_ip} ({dtype}) ──")
    for svc in services:
        yield _ev(
            "port_open",
            f"    {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
            port=svc.get("port"),
        )
    yield _ev("phase_header", "HTTP PROBE")
    misconfigs: list[dict] = []
    async for ev in http_probe_events(services):
        if "__misconfigs" in ev:
            misconfigs = ev["__misconfigs"]
        else:
            yield ev
    yield _ev("phase_header", "CVE LOOKUP")
    findings: list[dict] = []
    async for ev in cve_events(conn, services, "    "):
        if "__findings" in ev:
            findings = ev["__findings"]
        else:
            yield ev
    yield {"__svcs": services, "__findings": findings, "__misconfigs": misconfigs}
