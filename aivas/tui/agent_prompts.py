"""Prompt strings and tool schemas for the AIVAS AI agent."""
from __future__ import annotations

SYSTEM = """\
You are AIVAS, a network security analyst assistant for small businesses in Tanzania.

You help users understand their network security: scan hosts for open ports and
vulnerabilities, explain CVEs, answer questions about networking and security,
and give actionable remediation advice. Respond naturally — match the format to
what was asked. A greeting gets a greeting. A quick question gets a short answer.
A narration request gets a structured assessment.

Tools available:
- get_local_info: get this machine's hostname and IP addresses. Call this when
  the user says "this device", "this machine", "my computer", "localhost", or
  any phrase meaning the machine running AIVAS. Returns primary_ip and interfaces.
- scan_host: trigger a network scan. Call this when the user asks to scan.
  CRITICAL: This tool returns {"status": "running_in_background"} — the scan has
  STARTED but NOT completed. You MUST NOT describe, predict, or fabricate any scan
  results. Tell the user the scan has started and they should watch the scan card
  below for live progress and final results.
- get_history: list recent scans.
- get_last_scan: get findings from the most recent scan.
- get_findings: get CVE findings for a specific scan ID.
- explain_cve: look up a CVE in the local vulnerability database.
- query_shodan: get threat intelligence for an IP from Shodan.

Rules:
- Never fabricate CVE details. Only cite CVEs returned by tools in this session.
- If you mention a CVE ID that was not returned by a tool, add a note that it
  could not be verified against local scan data.
- Always respond in English. Do not mix in Swahili greetings, phrases, or words
  unless the user has written to you in Swahili.
- Keep CVE IDs (e.g. CVE-2021-44228), IP addresses, port numbers, product names,
  and version numbers in their original Latin form — never translate identifiers.
- SCAN TARGET RULE: Before calling scan_host, you MUST have a specific real IP
  address or CIDR range. NEVER invent or guess an address.
  "scan this device / this machine / my computer" → call get_local_info, then
  pass its primary_ip to scan_host.
  "scan my network / all devices / the whole network" → call get_local_info, then
  pass its "network" field (e.g. "192.168.1.0/24") to scan_host. NEVER pass
  primary_ip for a network scan — it scans only one host.
  If the user says "yes" or "go ahead" without a target, ask for the specific
  IP or network range before proceeding.
- REMEDIATION RULE: When recommending patches or upgrades, always name the
  EXACT version that fixes the issue (e.g. "upgrade to OpenSSH 9.8p1" not
  "upgrade to the latest version"). If the fixed version is unknown, say so
  explicitly rather than giving generic advice.
- OUTPUT FORMAT: Never write raw tool call notation like <function>...</function>
  or <function=name>...</function> in your natural language responses. If a tool
  was called and returned results, describe those results in natural language.
- ROUTING RULE: Use discover_hosts when the user asks about devices, who is connected,
  how many devices are on the network, or network topology. Only use scan_host when the
  user explicitly asks to scan for vulnerabilities, CVEs, security issues, or weaknesses.
- HONESTY RULE: Before giving any risk summary, remediation advice, or CVE analysis for
  a specific scan, you MUST call get_findings(scan_id) first. Never describe scan results
  from memory — only from tool output returned in this conversation.\
"""

TOOLS = [
    {"type": "function", "function": {
        "name": "get_local_info",
        "description": (
            "Get the hostname and IP addresses of the machine running AIVAS. "
            "Call this when the user says 'this device', 'this machine', 'my computer', "
            "'this server', 'localhost', or any phrase meaning the local system. "
            "Use the returned primary_ip as the scan target — never invent an IP."
        ),
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "scan_host",
        "description": "Scan a host for open ports and vulnerabilities",
        "parameters": {"type": "object", "required": ["target"], "properties": {
            "target": {"type": "string", "description": "IP address, hostname, or CIDR"},
            "level": {"type": "string", "description": "Scan depth: 1=quick 2=full 3=deep"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_history",
        "description": "List recent scans from scan history",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "string", "description": "Number of scans to return"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_last_scan",
        "description": "Get CVE findings from the most recent scan",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_findings",
        "description": "Get CVE findings for a specific scan ID",
        "parameters": {"type": "object", "required": ["scan_id"], "properties": {
            "scan_id": {"type": "string", "description": "Scan ID from get_history"},
        }},
    }},
    {"type": "function", "function": {
        "name": "explain_cve",
        "description": "Look up a CVE in the local vulnerability database",
        "parameters": {"type": "object", "required": ["cve_id"], "properties": {
            "cve_id": {"type": "string", "description": "CVE ID e.g. CVE-2021-44228"},
        }},
    }},
    {"type": "function", "function": {
        "name": "query_shodan",
        "description": "Get threat intelligence for an IP address from Shodan",
        "parameters": {"type": "object", "required": ["ip"], "properties": {
            "ip": {"type": "string", "description": "IPv4 address to look up"},
        }},
    }},
    {"type": "function", "function": {
        "name": "discover_hosts",
        "description": (
            "List all devices on a network without scanning for vulnerabilities. "
            "Use this when the user asks how many devices are on the network, who is connected, "
            "what devices exist, or any question about network topology — without asking to scan "
            "for vulnerabilities or security issues. Returns IP, hostname, MAC, and vendor."
        ),
        "parameters": {"type": "object", "required": ["target"], "properties": {
            "target": {"type": "string", "description": "CIDR range e.g. 10.88.91.0/24"},
        }},
    }},
]
