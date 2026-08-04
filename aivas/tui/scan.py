"""Scan pipeline: validation, nmap execution, CVE correlation, output."""
from __future__ import annotations
import asyncio
import re
import socket
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .app import AIVASApp
from .progress import StepProgress  # noqa: E402 — after TYPE_CHECKING block
from aivas.formatting import misconfig_table
from aivas.scorer import score_findings
from aivas.scanner.nse import scripts_for_level
from aivas.parser import parse_nmap_xml
from aivas.correlator import correlate
from aivas.history import save_scan
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
    import os
    import shutil
    import subprocess
    if not udp or os.geteuid() == 0:
        return False
    caps = subprocess.run(["getcap", shutil.which("nmap") or "nmap"],
                          capture_output=True, text=True).stdout
    return "cap_net_raw" not in caps
async def _run_nmap_threaded(app: "AIVASApp", target: str, scripts: str,
                              udp: bool, os_detect: bool, timeout: int = 300) -> str:
    """Run nmap via Popen; stores handle on app._scan_proc for ESC cancel."""
    import subprocess
    import shutil
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin, "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if os_detect:
        cmd += ["-O"]
    if scripts:
        cmd += ["--script", scripts]
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
    import sys
    import subprocess
    import shutil
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = ["sudo", nmap_bin, "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if scripts:
        cmd += ["--script", scripts]
    result = None
    with app.suspend():
        sys.stdout.write(f"\n[AIVAS] UDP scan requires root privileges.\n"
                         f"(One-time fix: sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin})\n\n")
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
    """Show risk score line and save scan to history (CVE table via modal)."""
    s = score_findings(findings)
    parts = [f"{v} {k.lower()}" for k, v in s.get("sev_counts", {}).items() if v]
    grade_col = "red" if s["grade"] in ("D", "F") else "green"
    line = (f"Risk Score: {s['score']}/100  Grade [{grade_col}]{s['grade']}[/{grade_col}]"
            f"  [#888888]— {s['total']} findings"
            + (" (" + ", ".join(parts) + ")" if parts else "") + "[/#888888]")
    app.tui_print(line)
    app.store_scan_output(line)
    try:
        save_scan(app.conn, target, findings)
        app.tui_print("[#888888]Scan saved to history (/history list)[/#888888]")
    except Exception:
        app.tui_print("[#888888]History save unavailable.[/#888888]")
    hist = getattr(app, "_scan_history", None)
    if hist is not None:
        hist.append({"target": target, "score": s["score"], "grade": s["grade"],
                     "top_cves": [f["cve_id"] for f in findings[:3]]})
        if len(hist) > 3:
            app._scan_history = hist[-3:]

async def _probe_misconfigs(app: "AIVASApp", services: list) -> list[dict]:
    """Probe HTTP/TLS services for misconfigs + port-based checks; return list."""
    from aivas.prober import probe_http_service
    from aivas.scanner.tls_check import parse_tls_misconfigs
    from aivas.scanner.misconfig_check import check_port_misconfigs

    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}
    misconfigs: list[dict] = []
    for svc in services:
        if (svc.get("service", "") in ("http", "https", "ssl")
                or svc.get("port") in _HTTP_PORTS):
            _is_ssl = "ssl" in svc.get("service", "") or svc.get("port") in (443, 8443)
            _scheme = "https" if _is_ssl else "http"
            try:
                _result = await asyncio.to_thread(
                    probe_http_service, svc["host"], svc["port"], _scheme)
                if _result.get("status") == "ok":
                    for f in _result["findings"]:
                        f["host"] = svc.get("host", "")
                        f["port"] = svc.get("port")
                    misconfigs.extend(_result["findings"])
            except Exception:
                pass
    misconfigs.extend(parse_tls_misconfigs(services))
    misconfigs.extend(check_port_misconfigs(services))
    if misconfigs:
        mc_table = misconfig_table("Configuration Issues", misconfigs)
        app.tui_print(mc_table)
        app.store_scan_output(mc_table)
    return misconfigs

async def run_scan_pipeline(app: "AIVASApp", target: str,
                             level: int = 2, udp: bool = False) -> None:
    """Run the full scan pipeline: validate → nmap → correlate → display."""
    ip_err = _bad_ip(target)
    if ip_err:
        app.tui_print(f"[red]Invalid target:[/red] {ip_err}")
        return
    if not _IPV4_RE.match(target.split('/')[0] if '/' in target else target):
        app.tui_print(f"[#888888]Resolving {target}…[/#888888]")
        await asyncio.sleep(0)
        if not await _resolves(target):
            app.tui_print(f"[red]Scan error:[/red] Cannot resolve hostname: {target!r}\n"
                          "[#888888]Check spelling or use an IP address directly.[/#888888]")
            return
    app.tui_print(f"\n[#2a2a2a]{'─' * 58}[/#2a2a2a]")
    app.tui_print(f"  [#4a9eff]▶[/#4a9eff] Scanning [bold #e0e0e0]{target}[/bold #e0e0e0]  [#888888]level {level}{' · UDP' if udp else ''}[/#888888]")
    app.tui_print(f"[#2a2a2a]{'─' * 58}[/#2a2a2a]")
    app._last_scan_text = f"# AIVAS Scan — {target}\n"
    app.set_scan_running(target)
    await asyncio.sleep(0)
    app._scan_task = asyncio.current_task()

    prog = StepProgress(app)
    await prog.step("Port discovery + service detection")
    use_sudo = await _nmap_needs_sudo(udp)
    try:
        xml = (await _run_nmap_sudo(app, target, scripts_for_level(level), udp)
               if use_sudo else
               await _run_nmap_threaded(app, target, scripts=scripts_for_level(level), udp=udp, os_detect=True))
    except asyncio.CancelledError:
        prog.fail("Port discovery + service detection", "cancelled")
        app.set_scan_idle()
        return
    except RuntimeError as exc:
        prog.fail("Port discovery + service detection", str(exc))
        app.set_scan_idle()
        return
    finally:
        app._scan_task = None
        if app._scan_proc:
            try:
                app._scan_proc.kill()
            except OSError:
                pass
            app._scan_proc = None
        app.set_scan_idle()

    try:
        services = parse_nmap_xml(xml)
    except Exception:
        prog.fail("Port discovery + service detection", "nmap output not valid XML")
        return
    if not services:
        prog.fail("Port discovery + service detection", "host unreachable or no open ports")
        app.tui_print(f"[yellow]{target}[/yellow]: no open ports — host may be offline or firewalled.\n"
                      "[#888888]Tip: scan a known-active IP, e.g. your router or default gateway.[/#888888]")
        return
    await prog.done("Port discovery + service detection", f"{len(services)} open port(s)")
    for svc in services:
        port = svc.get("port", "?")
        proto = svc.get("protocol", "tcp")
        product = svc.get("product") or svc.get("service") or "unknown"
        version = svc.get("version") or ""
        label = f"{product} {version}".strip()
        app.tui_print(f"    [#888888]{port}/{proto}[/#888888]  OPEN  [cyan]{label}[/cyan]")
        await asyncio.sleep(0.03)
    await prog.step("CVE correlation")
    os_hint = services[0].get("os_family") or None
    all_findings: list[dict] = []
    for svc in services:
        port = svc.get("port", "?")
        product = svc.get("product") or svc.get("service") or "unknown"
        version = svc.get("version") or ""
        label = f"{product} {version}".strip()
        app.tui_print(f"    [#888888]querying:[/#888888] {label} [#888888](port {port})[/#888888]")
        await asyncio.sleep(0.02)
        svc_findings = await asyncio.to_thread(correlate, app.conn, [svc], os_hint)
        probable = [f for f in svc_findings if f.get("confidence") in ("probable", "confirmed")]
        if probable:
            worst = max(probable, key=lambda f: f.get("cvss_score") or 0)
            sev_col = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "magenta"}.get(
                worst.get("cvss_severity", ""), "white"
            )
            app.tui_print(
                f"    [#888888]→[/#888888] {len(probable)} CVE(s) — worst: "
                f"[{sev_col}]{worst.get('cve_id','')}[/{sev_col}] "
                f"({worst.get('cvss_severity','')} {worst.get('cvss_score','')})"
            )
        else:
            app.tui_print("    [#888888]→ no CVEs matched[/#888888]")
        all_findings.extend(svc_findings)
        await asyncio.sleep(0.02)
    findings = [f for f in all_findings if f.get("confidence") in ("probable", "confirmed")][:30]
    await prog.done("CVE correlation", f"{len(findings)} CVE(s)" if findings else "0 CVEs")
    if findings:
        await _show_findings(app, target, findings)
    else:
        app.tui_print("[green]No CVEs matched at probable confidence.[/green]")
    await prog.step("Configuration checks")
    misconfigs = await _probe_misconfigs(app, services)
    await prog.done("Configuration checks", f"{len(misconfigs)} issue(s)" if misconfigs else "none")
    app._last_findings = findings
    app._last_misconfigs = misconfigs
    app._last_target = target
    from .screens import ScanResultScreen
    grade = score_findings(findings)["grade"] if findings else "A+"
    choice = await app.push_screen_wait(ScanResultScreen(target, grade, len(findings)))
    if choice:
        from .handlers import post_scan_handler
        await post_scan_handler(app, choice)
