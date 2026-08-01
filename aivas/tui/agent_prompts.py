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
- Match the user's language (Swahili or English). Mixed language — prefer the
  majority. Default to English when unclear.
- Keep CVE IDs (e.g. CVE-2021-44228), IP addresses, port numbers, product names,
  and version numbers in their original Latin form — never translate identifiers.\
"""

TOOLS = [
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
]
