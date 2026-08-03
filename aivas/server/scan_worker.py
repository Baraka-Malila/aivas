# aivas/server/scan_worker.py
"""Scan pipeline orchestrator — nmap + HTTP probe + CVE correlation, yields JSON events."""
from __future__ import annotations

import asyncio
import logging
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from typing import AsyncGenerator

_log = logging.getLogger("aivas.scan")

from aivas.history import save_scan
from aivas.parser import parse_nmap_xml
from aivas.scanner.nse import scripts_for_level
from aivas.scorer import score_findings
from aivas.server.scan_helpers import (
    _ev, _svc_label,
    cve_events, http_probe_events, scan_host,
    credential_scan_events,
)


async def _async_nmap(
    target: str, scripts: str, timeout: int = 300,
    fast: bool = False, os_detect: bool = True,
) -> str:
    """Run nmap as a cancellable async subprocess.

    When os_detect=True, appends -O. If nmap exits non-zero with 'root'
    in stderr, retries without -O (graceful degradation on non-root hosts).
    """
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if fast:
        nmap_host_timeout = max(timeout - 15, 30)
        cmd += [
            "-T4", "--version-intensity", "5",
            "--max-retries", "1",
            "--host-timeout", f"{nmap_host_timeout}s",
        ]
    if os_detect:
        cmd += ["-O"]
    if scripts:
        cmd += ["--script", scripts]

    async def _run(run_cmd: list[str]) -> tuple[bytes, bytes, int]:
        proc = await asyncio.create_subprocess_exec(
            *run_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            proc.kill()
            await proc.wait()
            raise
        return stdout, stderr, proc.returncode

    stdout, stderr, returncode = await _run(cmd)

    if returncode != 0:
        stderr_text = stderr.decode()
        if os_detect and "root" in stderr_text.lower() and "-O" in cmd:
            cmd = [c for c in cmd if c != "-O"]
            stdout, stderr, returncode = await _run(cmd)
            if returncode != 0:
                raise RuntimeError(
                    f"nmap exited {returncode}: {stderr.decode()[:300]}"
                )
        else:
            raise RuntimeError(f"nmap exited {returncode}: {stderr_text[:300]}")

    return stdout.decode()


async def _ping_sweep(target: str, timeout: int = 60) -> list[str]:
    """Return list of live host IPs via nmap -sn ping sweep."""
    nmap_bin = shutil.which("nmap") or "nmap"
    proc = await asyncio.create_subprocess_exec(
        nmap_bin, "-sn", "-oX", "-", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        proc.kill()
        await proc.wait()
        return []
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    try:
        root = ET.fromstring(stdout.decode())
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
    conn: sqlite3.Connection, target: str, level: int = 2,
    creds: dict | None = None, _partial_out: dict | None = None,
    user_id: int | None = None,
) -> AsyncGenerator[dict, None]:
    """Yield granular progress events then a single done or error event.

    If closed early via aclose() (user stop), any findings already correlated
    are saved to the DB and _partial_out is populated for the caller.
    """
    is_net = "/" in target
    scripts = scripts_for_level(level)
    _progress: list[str] = []
    all_services: list[dict] = []
    all_findings: list[dict] = []
    all_misconfigs: list[dict] = []
    _done = False

    def _emit(ev: dict) -> dict:
        if ev.get("text"):
            _progress.append(ev["text"])
        return ev

    try:
        yield _emit(_ev("phase_header", "INITIALIZING"))
        yield _emit(_ev("init", f"Initializing {'network' if is_net else 'host'} scan → {target}"))

        if is_net:
            yield _emit(_ev("phase_header", "HOST DISCOVERY"))
            yield _emit(_ev("discovery", f"Pinging {target} …"))
            live = await _ping_sweep(target)
            if live:
                yield _emit(_ev("hosts_found", f"  ▸ {len(live)} live host(s) found:"))
                for h in live:
                    yield _emit(_ev("host_up", f"    · {h}"))
            else:
                yield {
                    "type": "error",
                    "text": (
                        f"{target}: ping sweep found no live hosts. "
                        "ICMP may be blocked — try scanning a specific host IP directly."
                    ),
                }
                return
            for host_ip in live:
                yield _emit(_ev("phase_header", "PORT SCANNING"))
                async for ev in scan_host(conn, host_ip, scripts, _async_nmap, host_timeout=90, fast=True):
                    if "__svcs" in ev:
                        all_services.extend(ev["__svcs"])
                        all_findings.extend(ev["__findings"])
                        all_misconfigs.extend(ev["__misconfigs"])
                    elif ev.get("type") == "error":
                        err_text = ev.get("text", "scan failed")
                        _log.warning("host %s: %s", host_ip, err_text)
                        yield _emit(_ev("host_error", f"  {host_ip}: {err_text} — skipping host"))
                    else:
                        yield _emit(ev)
            if not all_services:
                yield {"type": "error", "text": f"{target}: no open ports found on any live host."}
                return
        else:
            yield _emit(_ev("phase_header", "PORT SCANNING"))
            yield _emit(_ev("ports", "Starting TCP port scan (top 1000 ports)…"))
            nmap_task = asyncio.create_task(_async_nmap(target, scripts))
            start = asyncio.get_event_loop().time()
            xml: str | None = None
            try:
                while not nmap_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(nmap_task), timeout=3.0)
                    except asyncio.TimeoutError:
                        elapsed = int(asyncio.get_event_loop().time() - start)
                        yield _emit(_ev("scanning", f"Port scan running… {elapsed}s elapsed"))
                xml = await nmap_task
            except Exception as exc:
                yield {"type": "error", "text": str(exc)}
                return
            finally:
                if not nmap_task.done():
                    nmap_task.cancel()
                    try:
                        await nmap_task
                    except (asyncio.CancelledError, Exception):
                        pass
            yield _emit(_ev("ports_done", "Port scan complete — parsing results"))
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
            yield _emit(_ev("open_ports", f"Found {len(services)} open port(s):"))
            for svc in services:
                yield _emit(_ev(
                    "port_open",
                    f"  {svc.get('port','?')}/{svc.get('protocol','tcp')} OPEN → {_svc_label(svc)}",
                    port=svc.get("port"),
                ))
            yield _emit(_ev("phase_header", "HTTP PROBE"))
            async for ev in http_probe_events(services):
                if "__misconfigs" in ev:
                    all_misconfigs = ev["__misconfigs"]
                else:
                    yield _emit(ev)
            credential_services: list[dict] = []
            if creds:
                yield _emit(_ev("phase_header", "CREDENTIAL SCAN"))
                async for ev in credential_scan_events(target, creds):
                    if "__credential_services" in ev:
                        credential_services = ev["__credential_services"]
                        yield _emit(_ev(
                            "credential_result",
                            f"  Enumerated {len(credential_services)} software item(s) via {creds.get('method','?').upper()}",
                        ))
                    elif "__ssh_hardening" in ev:
                        all_misconfigs.extend(ev["__ssh_hardening"])
                    elif "__credential_error" in ev:
                        yield _emit(_ev("credential_error", f"  ⚠ {ev['__credential_error']}"))
                        yield _emit(_ev("credential_fallback", "  Continuing with nmap results only"))
                    else:
                        yield _emit(ev)
            yield _emit(_ev("phase_header", "CVE LOOKUP"))
            async for ev in cve_events(conn, services + credential_services, "  "):
                if "__findings" in ev:
                    all_findings = ev["__findings"]
                else:
                    yield _emit(ev)
            all_services.extend(services)
            all_services.extend(credential_services)

        for f in all_findings:
            if not f.get("cve_id"):
                continue
            row = conn.execute("SELECT kev FROM cves WHERE cve_id=?", (f["cve_id"],)).fetchone()
            f["kev"] = bool(row and row["kev"])

        yield _emit(_ev("phase_header", "SCORING"))
        findings = [f for f in all_findings if f.get("confidence") in ("probable", "confirmed")][:30]
        yield _emit(_ev("scoring", f"Scoring {len(findings)} finding(s)…"))
        scored = score_findings(findings)
        grade, score = scored["grade"], scored["score"]
        yield _emit(_ev("grade", f"Risk score: {score}/100 — Grade {grade}"))
        scan_id = save_scan(conn, target, findings, user_id=user_id)
        _done = True
        yield {
            "type": "done",
            "target": target,
            "scan_id": scan_id,
            "score": score,
            "grade": grade,
            "service_count": len(all_services),
            "log": _progress,
            "services": [
                {"port": s.get("port"), "protocol": s.get("protocol", "tcp"),
                 "service": s.get("service", ""), "product": s.get("product", ""),
                 "version": s.get("version", ""), "host": s.get("host", "")}
                for s in all_services
            ],
            "findings": [
                {"cve_id": f["cve_id"], "cvss_score": f.get("cvss_score"),
                 "cvss_severity": f.get("cvss_severity"),
                 "description": f.get("description") or "",
                 "confidence": f.get("confidence"), "host": f.get("host", "")}
                for f in findings
            ],
            "misconfigs": all_misconfigs,
            "credential_scan": creds is not None,
        }
    finally:
        if not _done:
            _save_partial(conn, target, all_findings, all_services, all_misconfigs,
                          _progress, _partial_out, user_id=user_id)


def _save_partial(
    conn: sqlite3.Connection,
    target: str,
    all_findings: list[dict],
    all_services: list[dict],
    all_misconfigs: list[dict],
    progress: list[str],
    out: dict | None,
    user_id: int | None = None,
) -> None:
    """Save any correlated findings collected before cancellation."""
    partial = [f for f in all_findings if f.get("confidence") in ("probable", "confirmed")][:30]
    if not partial:
        return
    for f in partial:
        if f.get("cve_id"):
            row = conn.execute("SELECT kev FROM cves WHERE cve_id=?", (f["cve_id"],)).fetchone()
            f["kev"] = bool(row and row["kev"])
    scored = score_findings(partial)
    scan_id = save_scan(conn, target, partial, user_id=user_id)
    _log.info("Partial scan saved: scan_id=%d findings=%d", scan_id, len(partial))
    if out is not None:
        out.update({
            "scan_id": scan_id,
            "score": scored["score"],
            "grade": scored["grade"],
            "target": target,
            "service_count": len(all_services),
            "findings": [
                {"cve_id": f["cve_id"], "cvss_score": f.get("cvss_score"),
                 "cvss_severity": f.get("cvss_severity"),
                 "description": f.get("description") or "",
                 "confidence": f.get("confidence"), "host": f.get("host", "")}
                for f in partial
            ],
            "services": [
                {"port": s.get("port"), "protocol": s.get("protocol", "tcp"),
                 "service": s.get("service", ""), "product": s.get("product", ""),
                 "version": s.get("version", ""), "host": s.get("host", "")}
                for s in all_services
            ],
            "misconfigs": all_misconfigs,
            "log": progress,
        })
