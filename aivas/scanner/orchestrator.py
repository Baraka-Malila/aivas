import shutil
import subprocess


def run_scan(
    target: str,
    scripts: str = "",
    timeout: int = 300,
) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found — install nmap and retry.")

    cmd = ["nmap", "-sV", "-oX", "-", target]
    if scripts:
        cmd += ["--script", scripts]

    result = subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nmap exited {result.returncode}: {result.stderr.decode()}")
    return result.stdout.decode()
