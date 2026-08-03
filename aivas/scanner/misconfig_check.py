"""Port-based misconfiguration detection.

Pure function — no I/O, no async. Takes a list of parsed service dicts
(from parse_nmap_xml) and returns misconfig dicts in the same schema
used by aivas/prober/headers.py.
"""

_PORT_RULES: list[tuple[int, str, str, str, str, str]] = [
    (
        5555, "tcp", "CRITICAL",
        "Android Debug Bridge Exposed",
        "ADB over TCP (port 5555) allows unauthenticated remote shell access to "
        "an Android device. Enabled by Android developer mode with network debugging on.",
        "Disable Developer Options or turn off 'USB debugging' / 'Wireless debugging' "
        "under Android Developer Options. Firewall port 5555 from untrusted networks.",
    ),
    (
        23, "tcp", "HIGH",
        "Telnet Service Open",
        "Telnet transmits all data — including credentials — in plaintext. "
        "Any attacker on the same network can capture login sessions.",
        "Disable the Telnet service and replace with SSH.",
    ),
    (
        21, "tcp", "MEDIUM",
        "FTP Service Open",
        "FTP transmits credentials and file data in plaintext.",
        "Replace with SFTP (SSH file transfer) or FTPS (FTP over TLS).",
    ),
]


def check_port_misconfigs(services: list[dict]) -> list[dict]:
    """Return a list of misconfig dicts for any dangerous open ports found.

    Each returned dict includes host and port from the matching service.
    """
    findings: list[dict] = []
    for port, protocol, severity, title, description, recommendation in _PORT_RULES:
        for svc in services:
            if svc.get("port") == port and svc.get("protocol", "tcp") == protocol:
                findings.append({
                    "type": "misconfiguration",
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                    "host": svc.get("host", ""),
                    "port": port,
                })
    return findings
