import shutil
import subprocess


def run_scan(
    target: str,
    scripts: str = "",
    timeout: int = 300,
    udp: bool = False,
    os_detect: bool = False,
) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found — install nmap and retry.")

    cmd = ["nmap", "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if os_detect:
        cmd += ["-O"]
    if scripts:
        cmd += ["--script", scripts]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmap timed out after {timeout}s.")
    if result.returncode != 0:
        stderr = result.stderr.decode()
        # OS detection requires root — retry without -O rather than failing
        if os_detect and "root" in stderr.lower() and "-O" in cmd:
            cmd.remove("-O")
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"nmap timed out after {timeout}s.")
            if result.returncode != 0:
                raise RuntimeError(f"nmap exited {result.returncode}: {result.stderr.decode()}")
        else:
            raise RuntimeError(f"nmap exited {result.returncode}: {stderr}")
    return result.stdout.decode()
