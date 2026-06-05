import paramiko


def probe(
    host: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
) -> list[dict]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs: dict = {"hostname": host, "port": port, "username": username}
        if key_path:
            kwargs["key_filename"] = key_path
        elif password:
            kwargs["password"] = password
        client.connect(**kwargs)

        _, stdout, _ = client.exec_command(
            "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null"
        )
        os_info = stdout.read().decode(errors="replace").lower()

        if "debian" in os_info or "ubuntu" in os_info:
            _, stdout, _ = client.exec_command("dpkg -l 2>/dev/null")
            return _parse_dpkg(stdout.read().decode(errors="replace"), host)
        else:
            _, stdout, _ = client.exec_command("rpm -qa 2>/dev/null")
            return _parse_rpm(stdout.read().decode(errors="replace"), host)
    except paramiko.AuthenticationException:
        raise RuntimeError(f"SSH authentication failed for {username}@{host}")
    except Exception as exc:
        raise RuntimeError(f"SSH probe failed: {exc}") from exc
    finally:
        client.close()


def _parse_dpkg(output: str, host: str) -> list[dict]:
    services = []
    for line in output.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[1].split(":")[0]
        version = parts[2].lstrip("1:").split("-")[0].split("+")[0]
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "package", "product": name,
            "version": version, "nse_results": {}, "os_family": "Linux",
        })
    return services


def _parse_rpm(output: str, host: str) -> list[dict]:
    services = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.rsplit("-", 2)
        if len(parts) < 3:
            continue
        name = parts[0]
        version = parts[1].split(":")[0]
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "package", "product": name,
            "version": version, "nse_results": {}, "os_family": "Linux",
        })
    return services
