"""Scan pipeline for the web server: nmap + CVE correlation, yields granular JSON events."""
from __future__ import annotations

import asyncio
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import AsyncGenerator

from aivas.correlator import correlate
from aivas.history import save_scan
from aivas.parser import parse_nmap_xml
from aivas.scanner.nse import scripts_for_level
from aivas.scorer import score_findings


def _blocking_nmap(target: str, scripts: str, timeout: int = 300) -> str:
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if scripts:
        cmd += ["--script", scripts]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"nmap exited {result.returncode}: {result.stderr.decode()[:300]}")
    return result.stdout.decode()


def _ping_sweep(target: str, timeout: int = 60) -> list[str]:
    """Returns list of live host IPs via nmap -sn ping sweep."""
    nmap_bin = shutil.which("nmap") or "nmap"
    result = subprocess.run([nmap_bin, "-sn", "-oX", "-", target],
                            capture_output=True, timeout=timeout)
    if result.returncode != 0:
        return []
    try:
        root = ET.fromstring(result.stdout.decode())
        return [
            h.find("address[@addrtype='ipv4']").get("addr")
            for h in root.findall("host")
            if (h.find("status") is not None and h.find("status").get("state") == "up"
                and h.find("address[@addrtype='ipv4']") is not None)
        ]
    except Exception:
        return []


def _ev(phase: str, text: str, **extra) -> dict:
    return {"type": "progress", "phase": phase, "text": text, **extra}


def _svc_label(svc: dict) -> str:
    return f"{svc.get('product') or svc.get('service') or 'unknown'} {svc.get('version') or ''}".strip()


async def _cve_events(conn, services, indent="  "):
    """Yields CVE lookup progress events; returns list of all findings."""
    os_hint = services[0].get("os_family") or None
    all_findings: list[dict] = []
    for svc in services:
        yield _ev("cve_lookup", f"{indent}{_svc_label(svc)} (port {svc.get('port','?')})…")
        svc_findings = await asyncio.to_thread(correlate, conn, [svc], os_hint)
        probable = [f for f in svc_findings if f.get("confidence") in ("probable", "confirmed")]
        if probable:
            worst = max(probable, key=lambda f: f.get("cvss_score") or 0)
            yield _ev("cve_found", f"{indent}→ {len(probable)} CVE(s) — worst: "
                      f"{worst.get('cve_id','')} ({worst.get('cvss_severity','')} {worst.get('cvss_score','')})")
        else:
            yield _ev("cve_none", f"{indent}→ no CVEs matched")
        all_findings.extend(svc_findings)
    yield {"__findings": all_findings}


async def _scan_host_events(conn: sqlite3.Connection, host_ip: str, scripts: str):
    """Scans one host; yields progress events then sentinel {'__svcs':…,'__findings':…}."""
    fut = asyncio.ensure_future(asyncio.to_thread(_blocking_nmap, host_ip, scripts, 120))
    start = asyncio.get_event_loop().time()
    xml: str | None = None
    while True:
        done, _ = await asyncio.wait({fut}, timeout=3.0)
        if done:
            try:
                xml = fut.result()
            except Exception as exc:
                yield {"type": "error", "text": str(exc)}
                return
            break
        yield _ev("scanning", f"  {host_ip}: scanning… {int(asyncio.get_event_loop().time()-start)}s")
    try:
        services = parse_nmap_xml(xml)
    except Exception as exc:
        yield {"type": "error", "text": f"Parse error {host_ip}: {exc}"}
        return
    if not services:
        yield _ev("host_no_ports", f"  {host_ip}: no open ports found")
        yield {"__svcs": [], "__findings": []}
        return
    for svc in services:
        yield _ev("port_open",
                  f"    {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
                  port=svc.get("port"))
    findings: list[dict] = []
    async for ev in _cve_events(conn, services, "    "):
        if "__findings" in ev:
            findings = ev["__findings"]
        else:
            yield ev
    yield {"__svcs": services, "__findings": findings}


async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2
) -> AsyncGenerator[dict, None]:
    """Yields many granular progress events then a single done or error event."""
    is_net = "/" in target
    scripts = scripts_for_level(level)
    yield _ev("init", f"Initializing {'network' if is_net else 'host'} scan → {target}")
    all_services: list[dict] = []
    all_findings: list[dict] = []

    if is_net:
        yield _ev("discovery", f"Host discovery: pinging {target} …")
        live = await asyncio.to_thread(_ping_sweep, target)
        if live:
            yield _ev("hosts_found", f"  ▸ {len(live)} live host(s) found:")
            for h in live:
                yield _ev("host_up", f"    · {h}")
        else:
            yield _ev("hosts_found", "Ping sweep inconclusive — scanning range directly…")
            live = [target]
        for host_ip in live:
            yield _ev("host_scan", f"── Scanning {host_ip} ──")
            async for ev in _scan_host_events(conn, host_ip, scripts):
                if "__svcs" in ev:
                    all_services.extend(ev["__svcs"])
                    all_findings.extend(ev["__findings"])
                else:
                    yield ev
        if not all_services:
            yield {"type": "error", "text": f"{target}: no open ports found on any live host."}
            return
    else:
        yield _ev("ports", "Starting TCP port scan (top 1000 ports)…")
        fut = asyncio.ensure_future(asyncio.to_thread(_blocking_nmap, target, scripts))
        start = asyncio.get_event_loop().time()
        xml: str | None = None
        while True:
            done, _ = await asyncio.wait({fut}, timeout=3.0)
            if done:
                try:
                    xml = fut.result()
                except Exception as exc:
                    yield {"type": "error", "text": str(exc)}
                    return
                break
            yield _ev("scanning", f"Port scan running… {int(asyncio.get_event_loop().time()-start)}s elapsed")
        yield _ev("ports_done", "Port scan complete — parsing results")
        try:
            services = parse_nmap_xml(xml)
        except Exception as exc:
            yield {"type": "error", "text": f"Could not parse nmap output: {exc}"}
            return
        if not services:
            yield {"type": "error",
                   "text": f"{target}: no open ports found — host may be offline or firewalled."}
            return
        yield _ev("open_ports", f"Found {len(services)} open port(s):")
        for svc in services:
            yield _ev("port_open",
                      f"  {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
                      port=svc.get("port"))
        yield _ev("cve_start", f"Querying CVE database for {len(services)} service(s)…")
        async for ev in _cve_events(conn, services, "  "):
            if "__findings" in ev:
                all_findings = ev["__findings"]
            else:
                yield ev
        all_services.extend(services)

    findings = [f for f in all_findings if f.get("confidence") in ("probable", "confirmed")][:30]
    yield _ev("scoring", f"Scoring {len(findings)} finding(s)…")
    scored = score_findings(findings)
    grade, score = scored["grade"], scored["score"]
    yield _ev("grade", f"Risk score: {score}/100 — Grade {grade}")
    scan_id = save_scan(conn, target, findings)
    yield {
        "type": "done", "target": target, "scan_id": scan_id,
        "score": score, "grade": grade, "service_count": len(all_services),
        "services": [{"port": s.get("port"), "protocol": s.get("protocol", "tcp"),
                      "service": s.get("service", ""), "product": s.get("product", ""),
                      "version": s.get("version", ""), "host": s.get("host", "")}
                     for s in all_services],
        "findings": [{"cve_id": f["cve_id"], "cvss_score": f.get("cvss_score"),
                      "cvss_severity": f.get("cvss_severity"),
                      "description": f.get("description") or "",
                      "confidence": f.get("confidence"), "host": f.get("host", "")}
                     for f in findings],
    }
