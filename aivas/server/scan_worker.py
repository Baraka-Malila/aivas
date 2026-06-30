# aivas/server/scan_worker.py
"""Scan pipeline orchestrator — nmap + HTTP probe + CVE correlation, yields JSON events."""
from __future__ import annotations

import asyncio
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import AsyncGenerator

from aivas.correlator import correlate
from aivas.history import save_scan
from aivas.parser import parse_nmap_xml
from aivas.scanner.nse import scripts_for_level
from aivas.scorer import score_findings
from aivas.server.scan_helpers import (
    _ev, _svc_label,
    cve_events, http_probe_events, scan_host,
)


def _blocking_nmap(target: str, scripts: str, timeout: int = 300) -> str:
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if scripts:
        cmd += ["--script", scripts]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited {result.returncode}: {result.stderr.decode()[:300]}"
        )
    return result.stdout.decode()


def _ping_sweep(target: str, timeout: int = 60) -> list[str]:
    """Return list of live host IPs via nmap -sn ping sweep."""
    nmap_bin = shutil.which("nmap") or "nmap"
    result = subprocess.run(
        [nmap_bin, "-sn", "-oX", "-", target], capture_output=True, timeout=timeout
    )
    if result.returncode != 0:
        return []
    try:
        root = ET.fromstring(result.stdout.decode())
        return [
            h.find("address[@addrtype='ipv4']").get("addr")
            for h in root.findall("host")
            if (
                h.find("status") is not None
                and h.find("status").get("state") == "up"
                and h.find("address[@addrtype='ipv4']") is not None
            )
        ]
    except Exception:
        return []


async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2
) -> AsyncGenerator[dict, None]:
    """Yield granular progress events then a single done or error event."""
    is_net = "/" in target
    scripts = scripts_for_level(level)
    yield _ev("phase_header", "INITIALIZING")
    yield _ev("init", f"Initializing {'network' if is_net else 'host'} scan → {target}")
    all_services: list[dict] = []
    all_findings: list[dict] = []
    all_misconfigs: list[dict] = []

    if is_net:
        yield _ev("phase_header", "HOST DISCOVERY")
        yield _ev("discovery", f"Pinging {target} …")
        live = await asyncio.to_thread(_ping_sweep, target)
        if live:
            yield _ev("hosts_found", f"  ▸ {len(live)} live host(s) found:")
            for h in live:
                yield _ev("host_up", f"    · {h}")
        else:
            yield _ev("hosts_found", "Ping sweep inconclusive — scanning range directly…")
            live = [target]
        for host_ip in live:
            yield _ev("phase_header", "PORT SCANNING")
            async for ev in scan_host(conn, host_ip, scripts, _blocking_nmap):
                if "__svcs" in ev:
                    all_services.extend(ev["__svcs"])
                    all_findings.extend(ev["__findings"])
                    all_misconfigs.extend(ev["__misconfigs"])
                else:
                    yield ev
        if not all_services:
            yield {"type": "error", "text": f"{target}: no open ports found on any live host."}
            return
    else:
        yield _ev("phase_header", "PORT SCANNING")
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
            elapsed = int(asyncio.get_event_loop().time() - start)
            yield _ev("scanning", f"Port scan running… {elapsed}s elapsed")
        yield _ev("ports_done", "Port scan complete — parsing results")
        try:
            services = parse_nmap_xml(xml)
        except Exception as exc:
            yield {"type": "error", "text": f"Could not parse nmap output: {exc}"}
            return
        if not services:
            yield {
                "type": "error",
                "text": f"{target}: no open ports found — host may be offline or firewalled.",
            }
            return
        yield _ev("open_ports", f"Found {len(services)} open port(s):")
        for svc in services:
            yield _ev(
                "port_open",
                f"  {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
                port=svc.get("port"),
            )
        yield _ev("phase_header", "HTTP PROBE")
        async for ev in http_probe_events(services):
            if "__misconfigs" in ev:
                all_misconfigs = ev["__misconfigs"]
            else:
                yield ev
        yield _ev("phase_header", "CVE LOOKUP")
        async for ev in cve_events(conn, services, "  "):
            if "__findings" in ev:
                all_findings = ev["__findings"]
            else:
                yield ev
        all_services.extend(services)

    yield _ev("phase_header", "SCORING")
    findings = [
        f for f in all_findings if f.get("confidence") in ("probable", "confirmed")
    ][:30]
    yield _ev("scoring", f"Scoring {len(findings)} finding(s)…")
    scored = score_findings(findings)
    grade, score = scored["grade"], scored["score"]
    yield _ev("grade", f"Risk score: {score}/100 — Grade {grade}")
    scan_id = save_scan(conn, target, findings)
    yield {
        "type": "done",
        "target": target,
        "scan_id": scan_id,
        "score": score,
        "grade": grade,
        "service_count": len(all_services),
        "services": [
            {
                "port": s.get("port"),
                "protocol": s.get("protocol", "tcp"),
                "service": s.get("service", ""),
                "product": s.get("product", ""),
                "version": s.get("version", ""),
                "host": s.get("host", ""),
            }
            for s in all_services
        ],
        "findings": [
            {
                "cve_id": f["cve_id"],
                "cvss_score": f.get("cvss_score"),
                "cvss_severity": f.get("cvss_severity"),
                "description": f.get("description") or "",
                "confidence": f.get("confidence"),
                "host": f.get("host", ""),
            }
            for f in findings
        ],
        "misconfigs": all_misconfigs,
    }
