import socket
import subprocess

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def probe_http(host: str, port: int, ssl: bool = False, timeout: int = 5) -> dict:
    scheme = "https" if ssl else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False)
        return {
            "status": r.status_code,
            "server": r.headers.get("Server", ""),
            "title": _extract_title(r.text),
        }
    except Exception:
        return {"status": 0, "server": "", "title": ""}


def _extract_title(html: str) -> str:
    lo = html.lower()
    start = lo.find("<title>")
    end = lo.find("</title>")
    if start >= 0 and end > start:
        return html[start + 7:end].strip()[:100]
    return ""


def probe_banner(host: str, port: int, timeout: int = 3) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                return sock.recv(1024).decode(errors="replace").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def probe_ssl(host: str, port: int, timeout: int = 5) -> dict:
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-brief"],
            input=b"", capture_output=True, timeout=timeout,
        )
        out = (result.stdout + result.stderr).decode(errors="replace")
        return {"cn": _extract_cn(out), "raw": out[:500]}
    except Exception:
        return {"cn": "", "raw": ""}


def _extract_cn(text: str) -> str:
    for line in text.splitlines():
        if "subject" in line.lower() and "CN=" in line:
            for part in line.split(","):
                if "CN=" in part:
                    return part.split("CN=")[-1].strip()
    return ""
