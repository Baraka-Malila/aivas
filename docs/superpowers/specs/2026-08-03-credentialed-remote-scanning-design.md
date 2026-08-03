# Credentialed Remote Scanning Design

## Goal

Allow AIVAS to log into remote machines using SSH (Linux) or WinRM (Windows), enumerate installed software and running services from inside the machine, and feed those results through the existing CVE correlator. This is "credentialed scanning" — the same technique used by Nessus and OpenVAS to find vulnerabilities that a plain port scan cannot see (unpatched libraries, vulnerable kernels, outdated software not listening on any port).

## Architecture

Each scan runs in two phases:

**Phase 1 — Network perspective (existing):** nmap from outside discovers open ports, running services, and banner versions.

**Phase 2 — Internal perspective (new):** AIVAS connects to the target using provided credentials, runs read-only enumeration commands, and returns a second set of services with exact installed versions. Phase 2 results are merged with Phase 1 results before CVE correlation, replacing or supplementing nmap's version guesses with ground truth.

Phase 2 is optional — if no credentials are provided, the scan runs exactly as before.

## Scope

- **Linux targets:** SSH via paramiko. Commands: `cat /etc/os-release`, `dpkg -l` or `rpm -qa`, `uname -r`, `systemctl list-unit-files --type=service --state=enabled`.
- **Windows targets:** WinRM via pywinrm. PowerShell queries: `Win32_Product` (installed apps), `Win32_QuickFixEngineering` (KB patches), `Win32_OperatingSystem` (OS version), `Win32_Service` (running services).
- **Mac targets:** Out of scope for this sprint. SSH exists on Mac; can be added later with `brew list --versions` or `pkgutil --pkgs`.
- **Phones/mobile:** Out of scope. No SSH or WinRM.

## Components

### 1. `scanner/ssh_probe.py` (extend existing)

The current file does connection + package enumeration synchronously. Extend it to:

- Add `probe_async(host, username, password, key_path, port, timeout) -> list[dict]` — async wrapper using `asyncio.to_thread` so it does not block the event loop.
- Add kernel version: run `uname -r`, parse the version string, emit as a service with `product="linux-kernel"` and `version=<kernel_version>`.
- Add enabled services: run `systemctl list-unit-files --type=service --state=enabled --no-pager`, parse service names, emit each as a service with `product=<service_name>` and `version=""` (version unknown — correlator handles this gracefully).
- Add timeout enforcement: if any command takes longer than `timeout` seconds, cancel and continue.
- Return type: `list[dict]` using the same service dict shape as nmap (`host`, `port`, `protocol`, `service`, `product`, `version`, `nse_results`, `os_family`).
- Error handling: raise `CredentialError` (new exception class) for auth failures; raise `ConnectionError` for unreachable host; raise `ProbeError` for any other SSH error. All three have human-readable `.message` attributes suitable for displaying to the user.

**Service dict for kernel:**
```python
{
    "host": host, "port": 0, "protocol": "tcp",
    "service": "kernel", "product": "linux-kernel",
    "version": "6.8.0", "nse_results": {}, "os_family": "Linux",
}
```

**Service dict for installed package (existing pattern):**
```python
{
    "host": host, "port": 0, "protocol": "tcp",
    "service": "package", "product": "openssl",
    "version": "3.0.2", "nse_results": {}, "os_family": "Linux",
}
```

### 2. `scanner/winrm_probe.py` (new)

New module, mirrors ssh_probe.py in structure.

**Public API:**
```python
async def probe_async(
    host: str,
    username: str,
    password: str,
    port: int = 5985,
    use_ssl: bool = False,
    timeout: int = 60,
) -> list[dict]
```

**What it runs (via `pywinrm` `session.run_ps()`):**

```powershell
# Installed applications
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json

# KB patches (as product entries with KB number as version)
Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn | ConvertTo-Json

# OS version
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json

# Running services
Get-WmiObject -Class Win32_Service -Filter "State='Running'" | Select-Object Name, DisplayName, PathName | ConvertTo-Json
```

**Parsing:** Parse the JSON output from each query. For `Win32_Product`: `Name` → `product`, `Version` → `version`. For patches: `HotFixID` → `product` (e.g., `KB5034441`), `"patch"` → `service`. OS version → emit as `product="windows"` service.

**Error handling:** Same exception classes — `CredentialError`, `ConnectionError`, `ProbeError` — importable from a shared `scanner/probe_errors.py`.

**Dependencies:** `pip install pywinrm` added to `requirements.txt`. Import is lazy (inside the function) so the rest of AIVAS works if pywinrm is not installed; it raises `ProbeError("pywinrm not installed — run: pip install pywinrm")` in that case.

### 3. `scanner/probe_errors.py` (new, ~15 lines)

Shared exception types used by both ssh_probe and winrm_probe:

```python
class CredentialError(Exception):
    """Authentication failed — wrong username/password or key rejected."""

class ConnectionError(Exception):
    """Cannot reach the target host on the given port."""

class ProbeError(Exception):
    """Any other probe failure (command error, timeout, missing dependency)."""
```

### 4. `server/scan_helpers.py` (add one function)

New function `credential_scan_events(host, creds, timeout) -> AsyncGenerator`:

```python
async def credential_scan_events(
    host: str,
    creds: dict,          # {"method": "ssh"|"winrm", "username": str, "password": str, "key_path": str|None, "port": int}
    timeout: int = 90,
) -> AsyncGenerator[dict, None]
```

Logic:
1. Yield a progress event: `{"type": "progress", "text": "Connecting via SSH/WinRM to {host}…"}`
2. Call `ssh_probe.probe_async()` or `winrm_probe.probe_async()` based on `creds["method"]`
3. On success: yield `{"__credential_services": services}` where `services` is the list of dicts
4. On `CredentialError`: yield `{"__credential_error": "SSH authentication failed — check username/password or key path for {host}"}`
5. On `ConnectionError`: yield `{"__credential_error": "Cannot reach {host} on port {port} — is SSH/WinRM running?"}`
6. On `ProbeError`: yield `{"__credential_error": str(exc)}`
7. On `WinRM not enabled`: the `ConnectionError` message is `"WinRM not available on {host}. On that machine, run as Administrator: winrm quickconfig"`

### 5. `server/scan_worker.py` (extend `run_scan`)

After Phase 1 (nmap + HTTP probe), if credentials are present, call `credential_scan_events()`:

```python
async def run_scan(conn, target, level=2, creds=None) -> AsyncGenerator
```

New parameter `creds: dict | None`. If provided and target is a single host (not CIDR — credentials apply to a specific machine, not a range):

1. Run `credential_scan_events()` and collect `credential_services`
2. If a `__credential_error` is returned, add it to the scan log and continue without credential results
3. Merge `credential_services` into `all_services` before CVE correlation
4. Mark merged services with `"source": "credential"` so the done event can distinguish them
5. CVE correlation runs on the combined service list

For CIDR/network scans with credentials: apply the same credentials to each discovered host that responds to SSH/WinRM. Add a log entry per host attempt.

The done event gains one new field: `"credential_scan": true|false` to indicate whether phase 2 ran.

### 6. `server/main.py` (extend scan API)

The existing `POST /api/scan` endpoint and the WebSocket scan trigger both accept a body. Add `creds` field to the request schema:

```python
class ScanRequest(BaseModel):
    target: str
    level: int = 2
    creds: dict | None = None
    # creds shape: {"method": "ssh"|"winrm", "username": str, "password": str,
    #               "key_path": str|None, "port": int}
```

Credentials are not persisted server-side. They are used for the duration of the scan and discarded.

### 7. Chat agent tool: `remote_scan` (TUI + web)

**`tui/agent_prompts.py`** — add tool definition:

```python
{
    "type": "function",
    "function": {
        "name": "remote_scan",
        "description": (
            "Scan a specific host using SSH (Linux/Mac) or WinRM (Windows) credentials. "
            "Use when user says 'scan via SSH', 'scan as ubuntu', 'credentialed scan', "
            "or provides a username/password for a target. "
            "For Linux: method=ssh. For Windows: method=winrm."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "method": {"type": "string", "enum": ["ssh", "winrm"]},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "port": {"type": "integer", "description": "SSH port (default 22) or WinRM port (default 5985)"},
                "key_path": {"type": "string", "description": "Path to private key file for SSH key-based auth"},
            },
            "required": ["target", "method", "username"],
        },
    },
}
```

**`tui/agent.py`** — implement `_exec_tool` case for `remote_scan`:
- Build `creds` dict from tool args
- Call `run_scan(conn, target, level=2, creds=creds)` from the async pipeline
- Emit a `scan_triggered` intent so the UI shows scan progress

**Phase A routing prompt update** (`chat_stream.py` `_PHASE_A_SYSTEM`):
Add rule: "(6) User provides SSH/WinRM credentials or says 'scan as <user>' or 'via SSH' → call `remote_scan` with target, method, username, and any provided password/port."

### 8. `frontend/src/components/SettingsModal.jsx` (add Remote Targets section)

New collapsible section "Remote Targets" below the existing settings. Fields:

- **Target** (text input): IP or hostname
- **Method** (select): SSH / WinRM
- **Username** (text input)
- **Password** (password input, masked)
- **Port** (number input, default auto-fills to 22 for SSH, 5985 for WinRM)
- **SSH Key Path** (text input, optional, shown only when method=SSH)
- **Test Connection** button: calls `POST /api/probe/test` with the credentials — returns `{"ok": true}` or `{"error": "..."}` with the human-readable message
- **Save** button: stores the credential set to `localStorage` under `aivas_remote_targets` as a JSON array

Saved targets are shown as a list below the form. Each has a **Scan Now** button (triggers scan with those credentials) and a **Delete** button.

### 9. `server/main.py` — new test-connection endpoint

```
POST /api/probe/test
Body: {"method": "ssh"|"winrm", "host": str, "username": str, "password": str, "port": int, "key_path": str|None}
Response: {"ok": true} | {"ok": false, "error": "<human-readable message>"}
```

Calls `ssh_probe.probe_async()` or `winrm_probe.probe_async()` with a very short timeout (10s) and returns the result. Used by the Test Connection button in SettingsModal. Does not save or scan — test only.

## Data Flow (end-to-end)

```
User: "scan 192.168.1.50 via SSH as ubuntu"
  → Phase A (Groq): routes to remote_scan tool
  → tool_call event → web shows "Connecting via SSH…"
  → run_scan(target="192.168.1.50", creds={method:"ssh", username:"ubuntu", password:"..."})
      → Phase 1: nmap -sV 192.168.1.50 → [services from outside]
      → Phase 2: SSH in → dpkg -l, uname -r, systemctl → [services from inside]
      → merge services → CVE correlate → score → save
  → done event → ScanCard appears
  → ScanCard shows all CVEs including those found only via package enumeration
  → Confidence shows "confirmed" for credential-sourced findings
```

## Error Handling

| Failure | User sees |
|---|---|
| SSH port closed | "Cannot reach 192.168.1.50 on port 22 — is SSH running?" |
| Wrong SSH password | "SSH authentication failed — check username/password" |
| SSH key rejected | "SSH key authentication failed for ubuntu@192.168.1.50" |
| WinRM not configured | "WinRM not available on 192.168.1.50. On that machine, run as Administrator: winrm quickconfig" |
| Wrong WinRM password | "WinRM authentication failed for administrator@192.168.1.50" |
| pywinrm not installed | "pywinrm not installed on AIVAS machine. Run: pip install pywinrm" |
| Remote command fails | Logged in scan log; scan continues with Phase 1 results |
| Credential scan timeout | Logged; scan completes with Phase 1 results |

All errors appear as log entries in the ScanCard Scan Log. The scan never aborts due to a credential failure — it degrades to a plain nmap scan and tells the user why.

## Remote Machine Prerequisites

### Linux targets (SSH)

- **SSH server running.** On Ubuntu/Debian: `sudo systemctl start ssh`. On RHEL/CentOS: `sudo systemctl start sshd`. This is the default on most server installs.
- **User account exists.** Password or SSH key auth both work.
- **No special permissions needed** for `dpkg -l`, `rpm -qa`, `uname -r`, `cat /etc/os-release`. These run as a normal non-root user.
- **`systemctl list-unit-files`** requires systemd (all modern Linux distros have it).

### Windows targets (WinRM)

Run once as Administrator on the target machine:
```
winrm quickconfig
```
This enables WinRM, opens firewall ports 5985 (HTTP) and 5986 (HTTPS), and sets auto-start. That is the only prerequisite.

- Windows 10 / 11 / Server 2016+: WinRM is pre-installed, just needs enabling.
- The scanning user must be in the **Administrators** group.
- `Win32_Product` WMI query can be slow on machines with many installed apps (10–30 seconds). The timeout is set to 90 seconds to accommodate this.

### AIVAS control machine (yours)

New pip dependency:
```
pywinrm>=0.4.3
```

Add to `requirements.txt`. Paramiko is already present.

## What Appears in the Done Event

The `misconfigs` list remains unchanged (HTTP and any future probes). The `findings` list grows — credential-sourced findings have `"confidence": "confirmed"` (package version is ground truth). Nmap-sourced findings remain `"confidence": "probable"`.

The `credential_scan` field (`true/false`) is used by the web to optionally badge the ScanCard ("Credentialed scan" indicator next to the grade).

## Testing

- `tests/test_ssh_probe.py`: mock paramiko — test dpkg parsing, rpm parsing, kernel version parsing, `CredentialError` on auth failure, `ConnectionError` on refused connection.
- `tests/test_winrm_probe.py`: mock pywinrm session — test Win32_Product JSON parsing, patch parsing, `CredentialError`, `ConnectionError`, `ProbeError` when pywinrm missing.
- `tests/test_scan_helpers.py`: extend existing — test `credential_scan_events` yields correct events on success, yields `__credential_error` on each exception type.
- Integration: manual test against a real Linux device (your devices) and Windows machine.
