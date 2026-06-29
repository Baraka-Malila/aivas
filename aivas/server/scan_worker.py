"""Scan pipeline for the web server: runs nmap + CVE correlation, yields JSON events."""
from __future__ import annotations

import asyncio
import shutil
import sqlite3
import subprocess
from typing import AsyncGenerator

from aivas.correlator import correlate
from aivas.history import save_scan
from aivas.parser import parse_nmap_xml
from aivas.scanner.nse import scripts_for_level
from aivas.scorer import score_findings


async def _run_nmap(target: str, scripts: str, timeout: int = 300) -> str:
    """Run nmap -sV, return XML stdout. Raises RuntimeError on failure."""
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if scripts:
        cmd += ["--script", scripts]

    def _blocking() -> str:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(
                f"nmap exited {result.returncode}: {result.stderr.decode()[:200]}"
            )
        return result.stdout.decode()

    return await asyncio.to_thread(_blocking)


async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2
) -> AsyncGenerator[dict, None]:
    """Full scan pipeline as an async generator.

    Yields progress events then a single done (or error) terminal event.
    Event shapes:
      {"type": "progress", "text": str}
      {"type": "error",    "text": str}
      {"type": "done",     "target": str, "scan_id": int, "score": int,
       "grade": str, "service_count": int, "findings": list[dict]}
    """
    yield {"type": "progress", "text": f"Running port discovery on {target}…"}
    try:
        xml = await _run_nmap(target, scripts_for_level(level))
    except RuntimeError as exc:
        yield {"type": "error", "text": str(exc)}
        return

    try:
        services = parse_nmap_xml(xml)
    except Exception as exc:
        yield {"type": "error", "text": f"Could not parse nmap output: {exc}"}
        return

    if not services:
        yield {"type": "error",
               "text": f"{target}: no open ports found — host may be offline or firewalled."}
        return

    yield {"type": "progress",
           "text": f"Detected {len(services)} service(s). Correlating CVEs…"}

    os_hint = services[0].get("os_family") or None
    findings = [
        f for f in correlate(conn, services, os_hint=os_hint)
        if f.get("confidence") in ("probable", "confirmed")
    ][:30]

    yield {"type": "progress",
           "text": f"Found {len(findings)} CVE(s). Saving results…"}

    scored = score_findings(findings)
    scan_id = save_scan(conn, target, findings)

    yield {
        "type": "done",
        "target": target,
        "scan_id": scan_id,
        "score": scored["score"],
        "grade": scored["grade"],
        "service_count": len(services),
        "findings": [
            {
                "cve_id": f["cve_id"],
                "cvss_score": f.get("cvss_score"),
                "cvss_severity": f.get("cvss_severity"),
                "description": f.get("description") or "",
                "confidence": f.get("confidence"),
            }
            for f in findings
        ],
    }
