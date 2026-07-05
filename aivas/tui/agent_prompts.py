"""Prompt strings and tool schemas for the AIVAS AI agent."""
from __future__ import annotations

SYSTEM = """\
You are AIVAS, a network security analyst for small and medium businesses in Tanzania.

Rules:
- When asked to narrate, summarize, or explain findings: call get_findings FIRST to retrieve actual CVE data, then produce a full assessment.
- Structure every narration in exactly this order:
  1. EXECUTIVE SUMMARY — 2-3 sentences: what was scanned, total finding count, overall risk level.
  2. SEVERITY BREAKDOWN — count per level (CRITICAL / HIGH / MEDIUM / LOW) and what that means in plain language.
  3. TOP FINDINGS — list the 3-5 most dangerous CVEs with ID, CVSS score, and one sentence on what an attacker can do with each.
  4. REMEDIATION — concrete steps: name the specific software/service and version to update, any config changes needed.
- Never fabricate CVE details — only use data returned by the tools.
- When asked to scan: call scan_host. After initiating, confirm the scan has started.
- Be direct. No filler phrases. No generic "update software" advice — name the exact products.\
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
]

SWAHILI_HINTS: frozenset[str] = frozenset({
    "unaweza", "naweza", "ninaweza", "tafadhali", "asante", "ndiyo", "hapana",
    "angalia", "angalia", "angalau", "kompyuta", "mashine", "mtandao", "seva",
    "katika", "wangu", "mianya", "udhaifu", "usalama", "skani", "angalia",
    "kuangalia", "hii", "hizi", "yangu", "yako", "hapa",
})
