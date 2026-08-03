# AIVAS Scan Enhancements Design
**Date:** 2026-08-03

## Scope
Five self-contained scan improvements targeting the 15-minute demo scenario
(Kali scanning Asus TUF over LAN). Ordered by implementation size.

---

## 1. Admin Bootstrap

**Problem:** First registered user gets `role = "user"`. No way to become admin from UI.

**Fix:** In `auth.py::register_user()`, check user count before insert. If the table
is empty, override the role to `"admin"` unconditionally. This means whoever registers
first on a fresh install owns the system — correct behaviour for a self-hosted tool.

**Affected file:** `aivas/server/auth.py` — `register_user()`, 2 lines added.

**Test:** register two users; first gets `role="admin"`, second gets `role="user"`.

---

## 2. OS Fingerprinting in scan_worker.py

**Problem:** `orchestrator.py` already builds a root-fallback `-O` nmap command, but
`scan_worker.py::_async_nmap()` (the async path used by the web UI) never requests
OS detection. `parser.py` already extracts `osmatch → os_family`.

**Fix:** `_async_nmap()` gains `os_detect: bool = True`. When `os_detect=True`, append
`-O` to the nmap command. On non-zero return code, if `"root"` appears in stderr and
`"-O"` is in the command, remove `-O` and re-run (same logic as `orchestrator.py`).
Default to `True` — Kali runs as root so it will work; on non-root it silently drops
the flag.

**Data flow:**
- `parse_nmap_xml()` already extracts `os_family` per host (line 12-16 of `parser.py`)
- `os_family` travels in the service dict to `cve_events()` which passes it as `os_hint`
  to `correlate()` — already wired, no change needed downstream

**Affected files:**
- `aivas/server/scan_worker.py` — `_async_nmap()`, add `os_detect` param + root retry

**Test:** mock nmap returning XML with `<osmatch>` element; assert service dicts have
`os_family` populated.

---

## 3. TLS / Web Hardening NSE Scripts

**Problem:** Level 2 scans run `banner,ssh-auth-methods,http-title,...` but no TLS
inspection. Any host with HTTPS has potentially weak ciphers, expired certs, or missing
security headers — these are concrete high-value findings for the demo.

### 3a. NSE script additions

Add to `FULL_SCRIPTS` in `aivas/scanner/nse.py`:

```
ssl-enum-ciphers,ssl-cert,http-security-headers
```

These three scripts run against any port where nmap detects SSL/HTTP. They produce
structured output in the `nse_results` dict that `parse_nmap_xml()` already collects.

### 3b. TLS findings parser

New file `aivas/scanner/tls_check.py` — pure function, no async:

```python
def parse_tls_misconfigs(services: list[dict]) -> list[dict]:
```

Takes the list of parsed service dicts (each has `nse_results: dict[str, str]`).
Returns a list of misconfig dicts matching the existing schema from `prober/headers.py`
(without `host`/`port` — scan_helpers adds those):

```python
{
    "type": "misconfiguration",
    "title": str,
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "description": str,
    "recommendation": str,
}
```

**Parsing rules:**

| NSE script | Trigger | Severity | Title |
|---|---|---|---|
| `ssl-enum-ciphers` | output contains `TLSv1.0` | HIGH | Weak TLS 1.0 Supported |
| `ssl-enum-ciphers` | output contains `TLSv1.0` and no `TLSv1.2\|TLSv1.3` | CRITICAL | TLS 1.0 Only — No Modern TLS |
| `ssl-enum-ciphers` | output contains `RC4\|export\|DES` | CRITICAL | Broken Cipher Suite Detected |
| `ssl-cert` | output contains `Not valid after` date that is in the past | CRITICAL | SSL Certificate Expired |
| `ssl-cert` | output contains `Not valid after` date within 30 days | HIGH | SSL Certificate Expiring Soon |
| `http-security-headers` | output does not contain `Strict-Transport-Security` but port is 443/8443 | MEDIUM | Missing HSTS Header |
| `http-security-headers` | output does not contain `X-Content-Type-Options` | LOW | Missing X-Content-Type-Options |

Date parsing for `ssl-cert`: extract the `Not valid after:` line, parse with
`datetime.strptime`, compare to `datetime.now(UTC)`. On parse failure: skip.

### 3c. Integration point

`scan_helpers.py::http_probe_events()` is the natural home. After the existing HTTP
probe loop, call `parse_tls_misconfigs(services)` and extend `all_misconfigs`.
No new async needed — the NSE data is already in the service dicts.

Alternative considered: a separate `tls_probe_events()` generator. Rejected — the
NSE data is already collected by nmap; there's nothing async to do here.

**Affected files:**
- `aivas/scanner/nse.py` — add three scripts to `FULL_SCRIPTS`
- `aivas/scanner/tls_check.py` — new, ~70 lines
- `aivas/server/scan_helpers.py` — call `parse_tls_misconfigs` in `http_probe_events`

**Test:** unit-test `parse_tls_misconfigs()` with synthetic service dicts containing
sample NSE output strings. Assert correct severity and title for each trigger.

---

## 4. ADB Port 5555 as CRITICAL Misconfiguration

**Problem:** Port 5555 (Android Debug Bridge) is already detected and causes
`device_type_from_ports()` to return `"Android"`. But there is no security finding —
the user sees the device type but no alert that ADB is a serious threat.

ADB on TCP port 5555 grants unauthenticated remote shell on Android. It is enabled
only in developer mode but is commonly left on. On a LAN it is CRITICAL.

**Fix:** New file `aivas/scanner/misconfig_check.py` — pure function:

```python
def check_port_misconfigs(services: list[dict]) -> list[dict]:
```

Returns misconfig dicts (same schema as TLS misconfigs above, `"category": "port"`).

**Rules defined in this file:**

| Port | Protocol | Title | Severity | Description | Recommendation |
|---|---|---|---|---|---|
| 5555 | tcp | Android Debug Bridge Exposed | CRITICAL | ADB over TCP allows unauthenticated remote shell access to Android device. | Disable developer mode or turn off network debugging under Developer Options. |
| 23 | tcp | Telnet Open | HIGH | Telnet transmits credentials and data in plaintext. | Replace with SSH. |
| 21 | tcp | FTP Open | MEDIUM | FTP transmits credentials in plaintext. | Use SFTP or FTPS instead. |

This list is small intentionally (YAGNI). SSH misconfiguration is already handled by
the credentialed SSH probe hardening checks.

**Integration:** call `check_port_misconfigs(services)` in `http_probe_events()` (or
a renamed equivalent) alongside TLS check. Extend `all_misconfigs`.

**Affected files:**
- `aivas/scanner/misconfig_check.py` — new, ~40 lines
- `aivas/server/scan_helpers.py` — call `check_port_misconfigs`

**Test:** assert port 5555 → CRITICAL ADB finding; assert port 23 → HIGH telnet;
assert port 443 (no ADB, no telnet) → empty list.

---

## 5. UDP Device Discovery (mDNS / SSDP)

**Problem:** Phones and IoT devices on the LAN may have no TCP ports open, so the
ping sweep finds them but nmap returns no services. Device type stays "Unknown".

**Approach:** After the TCP ping sweep identifies live hosts, run a short UDP probe
using nmap NSE scripts targeting the two most informative protocols:
- UDP 5353 — mDNS (`dns-service-discovery` NSE) — identifies Apple devices, IoT
- UDP 1900 — SSDP (`upnp-info` NSE) — reveals friendly name and manufacturer

New file `aivas/scanner/udp_discover.py`:

```python
async def udp_device_info(
    hosts: list[str], timeout: int = 25
) -> dict[str, str]:
```

Returns `{ip: friendly_name}`. Runs a single nmap UDP command:

```
nmap -sU -p 5353,1900 --script dns-service-discovery,upnp-info
     --host-timeout 20s -oX - <space-separated hosts>
```

Parse XML output: for each host, extract:
1. `upnp-info` script output → look for `friendlyName:` line → use as device name
2. `dns-service-discovery` output → first service instance name → use as device name
3. Fallback: empty string (caller keeps existing device_type_from_ports inference)

**Integration in `scan_worker.py`:** In the network scan (`is_net=True`) branch, after
`_ping_sweep()` returns live hosts and before per-host TCP scan, fire
`udp_device_info(live)` with `asyncio.gather` (non-blocking, `return_exceptions=True`).
Store the result dict. When yielding `host_up` events, append the friendly name if
found: `"192.168.1.5 — iPhone [Baraka's Phone]"`.

**Failure handling:** if nmap exits non-zero (UDP requires root, or no UDP ports open),
log a debug message and return `{}`. Never block the main scan.

**Affected files:**
- `aivas/scanner/udp_discover.py` — new, ~60 lines
- `aivas/server/scan_worker.py` — call `udp_device_info` in network scan path

**Test:** mock nmap subprocess returning SSDP XML with a `friendlyName`; assert the
IP maps to the correct friendly name. Mock empty output → empty dict returned.

---

## Data Schema (misconfig dict)

All misconfigs — HTTP (existing), TLS (new), port-based (new) — share the schema
already established by `prober/headers.py` and `scan_helpers.py`:

```python
{
    "type": "misconfiguration",  # literal string, matches existing pattern
    "title": str,                # short display name
    "severity": str,             # CRITICAL | HIGH | MEDIUM | LOW
    "description": str,          # one-sentence explanation
    "recommendation": str,       # fix advice
    # host and port are added by scan_helpers.py when integrating results:
    "host": str,
    "port": int,
}
```

`tls_check.py` and `misconfig_check.py` return dicts **without** `host`/`port` —
`scan_helpers.py` adds them when extending `all_misconfigs`, matching the existing
pattern in `http_probe_events()` lines 136-139.

No frontend changes required — `ScanCard` already renders all misconfigs.

---

## Out of Scope (this spec)

- Fix scripts (OS detection accuracy prerequisite not met)
- Scheduled / periodic scans
- ScanCard inline analysis panels
- PyPI publish (mechanical step, not a design decision)
