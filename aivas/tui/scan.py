"""Scan pipeline: validation, nmap execution, CVE correlation, output."""
from __future__ import annotations
import asyncio
import re
import socket
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .app import AIVASApp
from .progress import StepProgress  # noqa: E402 — after TYPE_CHECKING block
_IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?$')
_KNOWN_FLAGS = {"--level", "--udp"}


def _bad_ip(target: str) -> str | None:
    """Return error string if target is an invalid IPv4, else None."""
    m = _IPV4_RE.match(target.split('/')[0] if '/' in target else target)
    if not m:
        return None
    if any(int(m.group(i)) > 255 for i in range(1, 5)):
        return f"Invalid IP address: {target!r} — each octet must be 0–255."
    return None

async def _resolves(host: str) -> bool:
    try:
        await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError):
        return False

async def _nmap_needs_sudo(udp: bool) -> bool:
    import os, shutil, subprocess
    if not udp or os.geteuid() == 0:
        return False
    caps = subprocess.run(["getcap", shutil.which("nmap") or "nmap"],
                          capture_output=True, text=True).stdout
    return "cap_net_raw" not in caps

async def _run_nmap_threaded(app: "AIVASApp", target: str, scripts: str,
                              udp: bool, os_detect: bool, timeout: int = 300) -> str:
    """Run nmap via Popen; stores handle on app._scan_proc for ESC cancel."""
    import subprocess, shutil
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if udp: cmd += ["-sU"]
    if os_detect: cmd += ["-O"]
    if scripts: cmd += ["--script", scripts]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    app._scan_proc = proc
    def _communicate() -> str:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            if proc.returncode == 0:
                return stdout.decode()
            err = stderr.decode()
            if os_detect and "root" in err.lower() and "-O" in cmd:
                cmd.remove("-O")
                r2 = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                app._scan_proc = r2
                stdout, stderr = r2.communicate(timeout=timeout)
                if r2.returncode != 0:
                    raise RuntimeError(f"nmap exited {r2.returncode}: {stderr.decode()}")
                return stdout.decode()
            raise RuntimeError(f"nmap exited {proc.returncode}: {err}")
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError(f"nmap timed out after {timeout}s.")
        finally:
            app._scan_proc = None
    return await asyncio.to_thread(_communicate)

async def _run_nmap_sudo(app: "AIVASApp", target: str, scripts: str,
                          udp: bool, timeout: int = 300) -> str:
    """Run sudo nmap with stdout XML capture (-oX -), return XML string."""
    import sys, subprocess, shutil
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = ["sudo", nmap_bin, "-sV", "-oX", "-", target]
    if udp: cmd += ["-sU"]
    if scripts: cmd += ["--script", scripts]
    result = None
    with app.suspend():
        sys.stdout.write(
            "\n[AIVAS] UDP scan requires root privileges.\n"
            f"(One-time fix: sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin})\n\n"
        )
        sys.stdout.flush()
        try:
            result = subprocess.run(cmd, stdin=sys.stdin, stdout=subprocess.PIPE,
                                    stderr=sys.stderr, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap timed out after {timeout}s.")
    if result is None:
        raise RuntimeError("nmap did not run (TUI suspend failed).")
    if result.returncode != 0:
        raise RuntimeError(f"nmap exited {result.returncode} — sudo denied or nmap missing?")
    xml = result.stdout.decode("utf-8", errors="replace")
    if not xml.strip():
        raise RuntimeError("nmap produced no output (check sudo permissions).")
    return xml

async def _show_findings(app: "AIVASApp", target: str, findings: list) -> None:
    """Display CVE table, score line, and save to history."""
    from aivas.formatting import cve_table
    from aivas.scorer import score_findings
    table = cve_table("Vulnerability Findings", findings, desc_max=55)
    app.tui_print(table)
    app.store_scan_output(table)
    s = score_findings(findings)
    parts = [f"{v} {k.lower()}" for k, v in s.get("sev_counts", {}).items() if v]
    grade_col = "red" if s["grade"] in ("D", "F") else "green"
    line = (f"Risk Score: {s['score']}/100  Grade [{grade_col}]{s['grade']}[/{grade_col}]"
            f"  [dim]— {s['total']} findings"
            + (" (" + ", ".join(parts) + ")" if parts else "") + "[/dim]")
    app.tui_print(line)
    app.store_scan_output(line)
    try:
        from aivas.history import save_scan
        save_scan(app.conn, target, findings)
        app.tui_print("[dim]Scan saved to history (/history list)[/dim]")
    except Exception:
        pass

async def _probe_misconfigs(app: "AIVASApp", services: list) -> list[dict]:
    """Probe HTTP services for misconfigs, display results, return list."""
    from aivas.formatting import misconfig_table
    misconfigs: list[dict] = []
    for svc in services:
        if (svc.get("service", "") in ("http", "https", "ssl")
                or svc.get("port") in (80, 443, 8080, 8443)):
            from aivas.prober import probe_http_service
            misconfigs.extend(await asyncio.to_thread(
                probe_http_service, svc["host"], svc["port"],
                "ssl" in svc.get("service", "")))
    if misconfigs:
        mc_table = misconfig_table("Configuration Issues", misconfigs)
        app.tui_print(mc_table)
        app.store_scan_output(mc_table)
    return misconfigs

async def run_scan_pipeline(app: "AIVASApp", target: str,
                             level: int = 2, udp: bool = False) -> None:
    """Run the full scan pipeline: validate → nmap → correlate → display."""
    from aivas.scanner.nse import scripts_for_level
    from aivas.parser import parse_nmap_xml
    from aivas.correlator import correlate
    from .progress import StepProgress

    if app._scan_task is not None and not app._scan_task.done():
        app.tui_print("[yellow]A scan is already running. Press ESC to cancel it first.[/yellow]")
        return
    ip_err = _bad_ip(target)
    if ip_err:
        app.tui_print(f"[red]Invalid target:[/red] {ip_err}")
        return
    if not _IPV4_RE.match(target.split('/')[0] if '/' in target else target):
        app.tui_print(f"[dim]Resolving {target}…[/dim]")
        await asyncio.sleep(0)
        if not await _resolves(target):
            app.tui_print(f"[red]Scan error:[/red] Cannot resolve hostname: {target!r}\n"
                          "[dim]Check spelling or use an IP address directly.[/dim]")
            return
    app.tui_print(f"Scanning [bold]{target}[/bold]  [dim](level {level}{', UDP' if udp else ''})[/dim]")
    app._last_scan_text = f"# AIVAS Scan — {target}\n"
    app.set_scan_running(target)
    await asyncio.sleep(0)
    app._scan_task = asyncio.current_task()

    prog = StepProgress(app)
    prog.step("Port discovery + service detection")
    use_sudo = await _nmap_needs_sudo(udp)
    try:
        xml = (await _run_nmap_sudo(app, target, scripts_for_level(level), udp)
               if use_sudo else
               await _run_nmap_threaded(app, target, scripts=scripts_for_level(level), udp=udp, os_detect=True))
    except asyncio.CancelledError:
        prog.fail("Port discovery + service detection", "cancelled"); app.set_scan_idle(); return
    except RuntimeError as exc:
        prog.fail("Port discovery + service detection", str(exc)); app.set_scan_idle(); return
    finally:
        app._scan_task = None
        if app._scan_proc:
            try: app._scan_proc.kill()
            except OSError: pass
            app._scan_proc = None
        app.set_scan_idle()

    try: services = parse_nmap_xml(xml)
    except Exception: prog.fail("Port discovery + service detection", "nmap output not valid XML"); return
    if not services: app.tui_print("[yellow]No open services found.[/yellow]"); return
    prog.done("Port discovery + service detection", f"{len(services)} service(s)")
    prog.step("CVE correlation")
    os_hint = services[0].get("os_family") or None
    findings = [f for f in correlate(app.conn, services, os_hint=os_hint)
                if f.get("confidence") in ("probable", "confirmed")][:30]
    prog.done("CVE correlation", f"{len(findings)} CVE(s)" if findings else "0 CVEs")
    if findings: await _show_findings(app, target, findings)
    else: app.tui_print("[green]No CVEs matched at probable confidence.[/green]")
    prog.step("Configuration checks")
    misconfigs = await _probe_misconfigs(app, services)
    prog.done("Configuration checks", f"{len(misconfigs)} issue(s)" if misconfigs else "none")
    app._last_findings = findings
    app._last_misconfigs = misconfigs
    app._last_target = target
