# Scan Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add admin bootstrap, OS fingerprinting, TLS/web hardening NSE checks, ADB port-5555 misconfiguration detection, and UDP mDNS/SSDP device discovery to AIVAS.

**Architecture:** New pure-function modules (`tls_check.py`, `misconfig_check.py`, `udp_discover.py`) slot into the existing scan pipeline via `scan_helpers.py::http_probe_events()` and `scan_worker.py`. All new misconfigs share the existing schema used by `prober/headers.py` and are rendered by the unchanged frontend `ScanCard`. OS fingerprinting is added to `_async_nmap()` with a root-error retry that matches `orchestrator.py`'s existing pattern.

**Tech Stack:** Python 3.10+, nmap (subprocess), standard library (`re`, `datetime`, `asyncio`), pytest, existing `parse_nmap_xml` parser.

## Global Constraints

- No file may exceed 200 lines of code — split if needed (CLAUDE.md rule; `scan_worker.py` is already at 313 lines, so keep additions minimal)
- All new misconfig dicts must have keys: `type`, `title`, `severity`, `description`, `recommendation`, `host`, `port`
- `severity` values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (uppercase, these exact strings)
- Tests use `asyncio.run()` not `@pytest.mark.asyncio` (matches existing test style in `tests/server/test_scan_worker.py`)
- Commit message format: `feat: <short description>` or `test: <short description>`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `aivas/server/auth.py` | Auto-promote first registered user to admin |
| Modify | `tests/server/test_auth.py` | Add two admin-bootstrap tests |
| Modify | `aivas/server/scan_worker.py` | Add `os_detect` param to `_async_nmap` + root retry; wire UDP discover |
| Create | `aivas/scanner/misconfig_check.py` | Port-based misconfig rules (ADB, Telnet, FTP) |
| Create | `tests/test_misconfig_check.py` | Unit tests for `check_port_misconfigs` |
| Create | `aivas/scanner/tls_check.py` | Parse TLS NSE output from service dicts into misconfigs |
| Create | `tests/test_tls_check.py` | Unit tests for `parse_tls_misconfigs` |
| Modify | `aivas/scanner/nse.py` | Append TLS scripts to `FULL_SCRIPTS` |
| Modify | `tests/test_nse.py` | Update `FULL_SCRIPTS` subset assertion |
| Modify | `aivas/server/scan_helpers.py` | Import and call `parse_tls_misconfigs` + `check_port_misconfigs` in `http_probe_events` |
| Create | `aivas/scanner/udp_discover.py` | Async UDP device discovery via nmap NSE |
| Create | `tests/test_udp_discover.py` | Unit tests for `udp_device_info` |

---

### Task 1: Admin Bootstrap

**Files:**
- Modify: `aivas/server/auth.py:44-64` (`register_user` function)
- Modify: `tests/server/test_auth.py` (add two tests at end)

**Interfaces:**
- Consumes: existing `register_user(conn, username, password, role="user") -> dict`
- Produces: same signature, same return shape — `role` in return dict is `"admin"` when the users table was empty at call time

- [ ] **Step 1: Write the two failing tests**

  Add to the bottom of `tests/server/test_auth.py`:

  ```python
  def test_first_user_becomes_admin(client):
      tc, _ = client
      r = tc.post("/api/auth/register", json={"username": "first", "password": "secret123"})
      assert r.status_code == 200
      assert r.json()["user"]["role"] == "admin"


  def test_second_user_stays_user(client):
      tc, _ = client
      tc.post("/api/auth/register", json={"username": "first", "password": "secret123"})
      r = tc.post("/api/auth/register", json={"username": "second", "password": "secret123"})
      assert r.status_code == 200
      assert r.json()["user"]["role"] == "user"
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  cd /home/cyberpunk/aivas
  python -m pytest tests/server/test_auth.py::test_first_user_becomes_admin tests/server/test_auth.py::test_second_user_stays_user -v
  ```

  Expected: both FAIL — first user currently gets `role="user"`.

- [ ] **Step 3: Implement the fix in `auth.py`**

  In `aivas/server/auth.py`, inside `register_user()`, add the user-count check before the INSERT. The existing function body starts with validation; add the count check just before `pw_hash = hash_password(plain)`:

  ```python
  def register_user(
      conn: sqlite3.Connection, username: str, password: str, role: str = "user"
  ) -> dict:
      username = username.strip()
      if not username or not password:
          raise HTTPException(status_code=400, detail="username and password are required")
      if len(password) < 6:
          raise HTTPException(status_code=400, detail="password must be at least 6 characters")
      existing = conn.execute(
          "SELECT id FROM users WHERE username=?", (username,)
      ).fetchone()
      if existing:
          raise HTTPException(status_code=409, detail="Username already taken")
      # First user on a fresh install becomes admin automatically
      user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
      if user_count == 0:
          role = "admin"
      pw_hash = hash_password(password)
      cur = conn.execute(
          "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
          (username, pw_hash, role),
      )
      conn.commit()
      return {"id": cur.lastrowid, "username": username, "role": role}
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  python -m pytest tests/server/test_auth.py -v
  ```

  Expected: all 11 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add aivas/server/auth.py tests/server/test_auth.py
  git commit -m "feat: first registered user becomes admin automatically"
  ```

---

### Task 2: OS Fingerprinting in `_async_nmap`

**Files:**
- Modify: `aivas/server/scan_worker.py:25-55` (`_async_nmap` function)
- Modify: `tests/server/test_scan_worker.py` (add one test)

**Interfaces:**
- Consumes: `_async_nmap(target, scripts, timeout=300, fast=False)` — existing callers
- Produces: `_async_nmap(target, scripts, timeout=300, fast=False, os_detect=True) -> str` — new optional param, backwards compatible

- [ ] **Step 1: Write the failing test**

  Add to `tests/server/test_scan_worker.py`:

  ```python
  from unittest.mock import AsyncMock, MagicMock, patch
  from aivas.server.scan_worker import _async_nmap


  def test_async_nmap_retries_without_os_flag_on_root_error():
      """When nmap exits non-zero with 'root' in stderr and -O in cmd, retries without -O."""
      call_count = [0]

      async def fake_create(*args, **kwargs):
          call_count[0] += 1
          proc = MagicMock()
          proc.kill = MagicMock()
          proc.wait = AsyncMock()
          if call_count[0] == 1:
              proc.returncode = 1
              proc.communicate = AsyncMock(
                  return_value=(b"", b"Warning: OS detection requires root privileges")
              )
          else:
              proc.returncode = 0
              proc.communicate = AsyncMock(return_value=(b"<nmaprun/>", b""))
          return proc

      async def run():
          with patch("asyncio.create_subprocess_exec", side_effect=fake_create):
              return await _async_nmap("10.0.0.1", "", os_detect=True)

      result = asyncio.run(run())
      assert result == "<nmaprun/>"
      assert call_count[0] == 2
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```bash
  python -m pytest tests/server/test_scan_worker.py::test_async_nmap_retries_without_os_flag_on_root_error -v
  ```

  Expected: FAIL — `_async_nmap` has no `os_detect` param.

- [ ] **Step 3: Implement `_async_nmap` with OS detect and root retry**

  Replace the entire `_async_nmap` function in `aivas/server/scan_worker.py` (lines 25-55):

  ```python
  async def _async_nmap(
      target: str, scripts: str, timeout: int = 300,
      fast: bool = False, os_detect: bool = True,
  ) -> str:
      """Run nmap as a cancellable async subprocess.

      When os_detect=True, appends -O. If nmap exits non-zero with 'root'
      in stderr, retries without -O (graceful degradation on non-root hosts).
      """
      nmap_bin = shutil.which("nmap") or "nmap"
      cmd = [nmap_bin, "-sV", "-oX", "-", target]
      if fast:
          nmap_host_timeout = max(timeout - 15, 30)
          cmd += [
              "-T4", "--version-intensity", "5",
              "--max-retries", "1",
              "--host-timeout", f"{nmap_host_timeout}s",
          ]
      if os_detect:
          cmd += ["-O"]
      if scripts:
          cmd += ["--script", scripts]

      async def _run(run_cmd: list[str]) -> tuple[bytes, bytes, int]:
          proc = await asyncio.create_subprocess_exec(
              *run_cmd,
              stdout=asyncio.subprocess.PIPE,
              stderr=asyncio.subprocess.PIPE,
          )
          try:
              stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
          except (asyncio.TimeoutError, asyncio.CancelledError):
              proc.kill()
              await proc.wait()
              raise
          return stdout, stderr, proc.returncode

      stdout, stderr, returncode = await _run(cmd)

      if returncode != 0:
          stderr_text = stderr.decode()
          if os_detect and "root" in stderr_text.lower() and "-O" in cmd:
              cmd = [c for c in cmd if c != "-O"]
              stdout, stderr, returncode = await _run(cmd)
              if returncode != 0:
                  raise RuntimeError(
                      f"nmap exited {returncode}: {stderr.decode()[:300]}"
                  )
          else:
              raise RuntimeError(f"nmap exited {returncode}: {stderr_text[:300]}")

      return stdout.decode()
  ```

- [ ] **Step 4: Run all scan_worker tests**

  ```bash
  python -m pytest tests/server/test_scan_worker.py -v
  ```

  Expected: all tests PASS (existing tests patched `_async_nmap` directly, so they still work).

- [ ] **Step 5: Commit**

  ```bash
  git add aivas/server/scan_worker.py tests/server/test_scan_worker.py
  git commit -m "feat: add OS fingerprinting to async nmap with root-error fallback"
  ```

---

### Task 3: Port Misconfiguration Check

**Files:**
- Create: `aivas/scanner/misconfig_check.py`
- Create: `tests/test_misconfig_check.py`

**Interfaces:**
- Consumes: `services: list[dict]` — each dict has at minimum `host: str`, `port: int`, `protocol: str`
- Produces:
  ```python
  def check_port_misconfigs(services: list[dict]) -> list[dict]
  # Returns list of misconfig dicts with keys:
  # type, title, severity, description, recommendation, host, port
  ```

- [ ] **Step 1: Write the failing tests**

  Create `tests/test_misconfig_check.py`:

  ```python
  """Tests for port-based misconfiguration detection."""
  from aivas.scanner.misconfig_check import check_port_misconfigs


  def _svc(port: int, host: str = "10.0.0.1", protocol: str = "tcp") -> dict:
      return {"host": host, "port": port, "protocol": protocol}


  def test_adb_port_5555_is_critical():
      result = check_port_misconfigs([_svc(5555)])
      assert len(result) == 1
      assert result[0]["severity"] == "CRITICAL"
      assert result[0]["port"] == 5555
      assert result[0]["host"] == "10.0.0.1"
      assert result[0]["type"] == "misconfiguration"


  def test_adb_title_mentions_adb():
      result = check_port_misconfigs([_svc(5555)])
      assert "ADB" in result[0]["title"] or "Android" in result[0]["title"]


  def test_telnet_port_23_is_high():
      result = check_port_misconfigs([_svc(23)])
      assert len(result) == 1
      assert result[0]["severity"] == "HIGH"
      assert result[0]["port"] == 23


  def test_ftp_port_21_is_medium():
      result = check_port_misconfigs([_svc(21)])
      assert len(result) == 1
      assert result[0]["severity"] == "MEDIUM"
      assert result[0]["port"] == 21


  def test_safe_port_returns_empty():
      result = check_port_misconfigs([_svc(443), _svc(22)])
      assert result == []


  def test_multiple_vulnerable_ports():
      result = check_port_misconfigs([_svc(5555), _svc(23)])
      assert len(result) == 2
      severities = {r["severity"] for r in result}
      assert "CRITICAL" in severities
      assert "HIGH" in severities


  def test_recommendation_field_present():
      result = check_port_misconfigs([_svc(5555)])
      assert "recommendation" in result[0]
      assert len(result[0]["recommendation"]) > 0


  def test_udp_port_does_not_trigger_tcp_rule():
      result = check_port_misconfigs([_svc(5555, protocol="udp")])
      assert result == []
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  python -m pytest tests/test_misconfig_check.py -v
  ```

  Expected: all FAIL — module does not exist.

- [ ] **Step 3: Implement `misconfig_check.py`**

  Create `aivas/scanner/misconfig_check.py`:

  ```python
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
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  python -m pytest tests/test_misconfig_check.py -v
  ```

  Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add aivas/scanner/misconfig_check.py tests/test_misconfig_check.py
  git commit -m "feat: add port-based misconfig check (ADB/Telnet/FTP)"
  ```

---

### Task 4: TLS Check

**Files:**
- Create: `aivas/scanner/tls_check.py`
- Create: `tests/test_tls_check.py`

**Interfaces:**
- Consumes: `services: list[dict]` — each has `nse_results: dict[str, str]`, `host: str`, `port: int`
- Produces:
  ```python
  def parse_tls_misconfigs(services: list[dict]) -> list[dict]
  # Returns misconfig dicts with type/title/severity/description/recommendation/host/port
  ```

- [ ] **Step 1: Write the failing tests**

  Create `tests/test_tls_check.py`:

  ```python
  """Tests for TLS NSE output parsing."""
  from aivas.scanner.tls_check import parse_tls_misconfigs
  from datetime import datetime, timezone, timedelta


  def _svc(nse: dict, host: str = "10.0.0.1", port: int = 443) -> dict:
      return {"host": host, "port": port, "protocol": "tcp", "nse_results": nse}


  # --- ssl-enum-ciphers tests ---

  def test_tls10_with_modern_is_high():
      nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:\nTLSv1.2:\n  ciphers:"}
      result = parse_tls_misconfigs([_svc(nse)])
      sevs = [r["severity"] for r in result]
      assert "HIGH" in sevs
      assert "CRITICAL" not in sevs


  def test_tls10_only_is_critical():
      nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:"}
      result = parse_tls_misconfigs([_svc(nse)])
      sevs = [r["severity"] for r in result]
      assert "CRITICAL" in sevs


  def test_broken_cipher_rc4_is_critical():
      nse = {"ssl-enum-ciphers": "TLSv1.2:\n  TLS_RSA_WITH_RC4_128_SHA"}
      result = parse_tls_misconfigs([_svc(nse)])
      assert any(r["severity"] == "CRITICAL" for r in result)


  def test_no_cipher_issues_returns_empty():
      nse = {"ssl-enum-ciphers": "TLSv1.2:\n  ciphers:\nTLSv1.3:\n  ciphers:"}
      result = parse_tls_misconfigs([_svc(nse)])
      assert result == []


  # --- ssl-cert expiry tests ---

  def test_expired_cert_is_critical():
      past = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
      nse = {"ssl-cert": f"Subject: commonName=example.com\nNot valid after:  {past}"}
      result = parse_tls_misconfigs([_svc(nse)])
      assert any(r["severity"] == "CRITICAL" and "Expired" in r["title"] for r in result)


  def test_expiring_soon_cert_is_high():
      soon = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%S")
      nse = {"ssl-cert": f"Not valid after:  {soon}"}
      result = parse_tls_misconfigs([_svc(nse)])
      assert any(r["severity"] == "HIGH" and "Expiring" in r["title"] for r in result)


  def test_valid_cert_returns_empty():
      future = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
      nse = {"ssl-cert": f"Not valid after:  {future}"}
      result = parse_tls_misconfigs([_svc(nse)])
      assert result == []


  # --- http-security-headers tests ---

  def test_missing_hsts_on_443_is_medium():
      nse = {"http-security-headers": "X-Frame-Options: SAMEORIGIN\nX-Content-Type-Options: nosniff"}
      result = parse_tls_misconfigs([_svc(nse, port=443)])
      assert any(r["severity"] == "MEDIUM" and "HSTS" in r["title"] for r in result)


  def test_hsts_present_no_medium():
      nse = {"http-security-headers": "Strict-Transport-Security: max-age=31536000"}
      result = parse_tls_misconfigs([_svc(nse, port=443)])
      assert not any("HSTS" in r.get("title", "") for r in result)


  def test_non_tls_port_no_hsts_check():
      # HSTS only meaningful on 443/8443
      nse = {"http-security-headers": "X-Frame-Options: SAMEORIGIN"}
      result = parse_tls_misconfigs([_svc(nse, port=80)])
      assert not any("HSTS" in r.get("title", "") for r in result)


  def test_no_nse_results_returns_empty():
      result = parse_tls_misconfigs([_svc({})])
      assert result == []


  def test_host_and_port_in_output():
      nse = {"ssl-enum-ciphers": "TLSv1.0:\n  ciphers:"}
      result = parse_tls_misconfigs([_svc(nse, host="192.168.1.5", port=8443)])
      assert result[0]["host"] == "192.168.1.5"
      assert result[0]["port"] == 8443
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  python -m pytest tests/test_tls_check.py -v
  ```

  Expected: all FAIL — module does not exist.

- [ ] **Step 3: Implement `tls_check.py`**

  Create `aivas/scanner/tls_check.py`:

  ```python
  """Parse TLS-related NSE script output from nmap service dicts into misconfigs.

  Pure function — no I/O, no async. Reads nse_results already collected by
  parse_nmap_xml() and returns misconfig dicts in the schema used by prober/headers.py.
  """
  from __future__ import annotations

  import re
  from datetime import datetime, timezone, timedelta

  _AFTER_RE = re.compile(
      r"Not valid after\s*:?\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2})",
      re.IGNORECASE,
  )
  _BROKEN_CIPHERS = ("RC4", "export", " DES", " NULL")
  _TLS_HTTPS_PORTS = frozenset({443, 8443})


  def parse_tls_misconfigs(services: list[dict]) -> list[dict]:
      """Return misconfig dicts for TLS issues found in NSE output of each service."""
      findings: list[dict] = []
      for svc in services:
          nse = svc.get("nse_results") or {}
          host = svc.get("host", "")
          port = svc.get("port", 0)

          enum_out = nse.get("ssl-enum-ciphers", "")
          if enum_out:
              findings.extend(_check_ciphers(enum_out, host, port))

          cert_out = nse.get("ssl-cert", "")
          if cert_out:
              findings.extend(_check_cert_expiry(cert_out, host, port))

          headers_out = nse.get("http-security-headers", "")
          if headers_out:
              findings.extend(_check_security_headers(headers_out, host, port))

      return findings


  def _check_ciphers(output: str, host: str, port: int) -> list[dict]:
      has_broken = any(c in output for c in _BROKEN_CIPHERS)
      has_tls10 = "TLSv1.0" in output
      has_modern = "TLSv1.2" in output or "TLSv1.3" in output

      results = []
      if has_broken:
          results.append({
              "type": "misconfiguration",
              "title": "Broken Cipher Suite Detected",
              "severity": "CRITICAL",
              "description": (
                  "The TLS configuration includes cryptographically broken ciphers "
                  "(RC4, export-grade, DES, or NULL). These can be exploited to "
                  "decrypt traffic."
              ),
              "recommendation": (
                  "Disable all RC4, export, DES, and NULL cipher suites in your "
                  "TLS/SSL configuration. Allow only TLS 1.2+ with AEAD ciphers."
              ),
              "host": host,
              "port": port,
          })
      elif has_tls10 and not has_modern:
          results.append({
              "type": "misconfiguration",
              "title": "TLS 1.0 Only — No Modern TLS",
              "severity": "CRITICAL",
              "description": (
                  "Only TLS 1.0 is enabled. TLS 1.0 is deprecated (RFC 8996) and "
                  "vulnerable to BEAST and POODLE attacks. No TLS 1.2 or 1.3 detected."
              ),
              "recommendation": "Enable TLS 1.2 and TLS 1.3; disable TLS 1.0 and 1.1.",
              "host": host,
              "port": port,
          })
      elif has_tls10:
          results.append({
              "type": "misconfiguration",
              "title": "Weak TLS 1.0 Supported",
              "severity": "HIGH",
              "description": (
                  "TLS 1.0 is still accepted alongside modern TLS versions. "
                  "TLS 1.0 is deprecated (RFC 8996) and should be disabled."
              ),
              "recommendation": "Disable TLS 1.0 and TLS 1.1 in your server TLS configuration.",
              "host": host,
              "port": port,
          })
      return results


  def _check_cert_expiry(output: str, host: str, port: int) -> list[dict]:
      m = _AFTER_RE.search(output)
      if not m:
          return []
      date_str = m.group(1)[:10]  # Take YYYY-MM-DD portion
      try:
          expiry = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
      except ValueError:
          return []
      now = datetime.now(timezone.utc)
      days_left = (expiry - now).days
      if days_left < 0:
          return [{
              "type": "misconfiguration",
              "title": "SSL Certificate Expired",
              "severity": "CRITICAL",
              "description": f"The SSL certificate expired on {date_str}. Clients will see security warnings.",
              "recommendation": "Renew the SSL certificate immediately.",
              "host": host,
              "port": port,
          }]
      if days_left <= 30:
          return [{
              "type": "misconfiguration",
              "title": "SSL Certificate Expiring Soon",
              "severity": "HIGH",
              "description": (
                  f"The SSL certificate expires on {date_str} ({days_left} day(s) remaining). "
                  "Clients will see warnings once it expires."
              ),
              "recommendation": "Renew the SSL certificate before it expires.",
              "host": host,
              "port": port,
          }]
      return []


  def _check_security_headers(output: str, host: str, port: int) -> list[dict]:
      results = []
      if port in _TLS_HTTPS_PORTS and "Strict-Transport-Security" not in output:
          results.append({
              "type": "misconfiguration",
              "title": "Missing HSTS Header",
              "severity": "MEDIUM",
              "description": (
                  "The Strict-Transport-Security header is absent. Without HSTS, "
                  "browsers may access the site over plain HTTP, enabling downgrade attacks."
              ),
              "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
              "host": host,
              "port": port,
          })
      if "X-Content-Type-Options" not in output:
          results.append({
              "type": "misconfiguration",
              "title": "Missing X-Content-Type-Options",
              "severity": "LOW",
              "description": "X-Content-Type-Options: nosniff is absent, allowing MIME-type sniffing.",
              "recommendation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
              "host": host,
              "port": port,
          })
      return results
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  python -m pytest tests/test_tls_check.py -v
  ```

  Expected: all 12 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add aivas/scanner/tls_check.py tests/test_tls_check.py
  git commit -m "feat: add TLS NSE output parser for cipher/cert/header misconfigs"
  ```

---

### Task 5: NSE Script Additions + scan_helpers Integration

**Files:**
- Modify: `aivas/scanner/nse.py` (add TLS scripts to `FULL_SCRIPTS`)
- Modify: `tests/test_nse.py` (update assertion — `FULL_SCRIPTS` now contains extra scripts)
- Modify: `aivas/server/scan_helpers.py` (call `parse_tls_misconfigs` + `check_port_misconfigs`)

**Interfaces:**
- Consumes: `check_port_misconfigs(services: list[dict]) -> list[dict]` from Task 3
- Consumes: `parse_tls_misconfigs(services: list[dict]) -> list[dict]` from Task 4
- Produces: `http_probe_events(services)` now includes TLS and port misconfigs in its `__misconfigs` sentinel — no signature change

- [ ] **Step 1: Update the NSE test for new scripts**

  In `tests/test_nse.py`, the test `test_quick_scripts_is_subset_of_full` asserts quick ⊆ full.
  That test still passes. But the FULL_SCRIPTS constant will change, so update the file to add
  a new test that asserts the TLS scripts are present:

  ```python
  # Add this test to tests/test_nse.py:
  def test_full_scripts_includes_tls_checks():
      for script in ("ssl-enum-ciphers", "ssl-cert", "http-security-headers"):
          assert script in FULL_SCRIPTS, f"{script} missing from FULL_SCRIPTS"
  ```

- [ ] **Step 2: Run new test to verify it fails**

  ```bash
  python -m pytest tests/test_nse.py::test_full_scripts_includes_tls_checks -v
  ```

  Expected: FAIL — scripts not yet in `FULL_SCRIPTS`.

- [ ] **Step 3: Update `aivas/scanner/nse.py`**

  Replace the `FULL_SCRIPTS` constant (append the three TLS scripts):

  ```python
  QUICK_SCRIPTS = "banner,ssh-auth-methods,http-title"

  FULL_SCRIPTS = (
      "banner,ssh-auth-methods,http-title,"
      "http-shellshock,http-vuln-cve2017-5638,"
      "smb-vuln-ms17-010,smb-vuln-cve2009-3103,"
      "ftp-vsftpd-backdoor,ftp-proftpd-backdoor,"
      "ssl-enum-ciphers,ssl-cert,http-security-headers"
  )

  UDP_SCRIPTS = "snmp-info,nbstat"


  def scripts_for_level(level: int) -> str:
      if level == 1:
          return QUICK_SCRIPTS
      return FULL_SCRIPTS
  ```

- [ ] **Step 4: Run all NSE tests**

  ```bash
  python -m pytest tests/test_nse.py -v
  ```

  Expected: all 5 tests PASS (quick ⊆ full still holds; new TLS test passes).

- [ ] **Step 5: Wire the checks into `scan_helpers.py::http_probe_events`**

  In `aivas/server/scan_helpers.py`, add two imports at the top of the file (after existing imports):

  ```python
  from aivas.scanner.tls_check import parse_tls_misconfigs
  from aivas.scanner.misconfig_check import check_port_misconfigs
  ```

  Inside `http_probe_events`, **replace** the final two lines (the http_clean message and
  the sentinel yield) with four new lines that run TLS/port checks first, then emit
  "clean" only if truly nothing was found:

  Current ending of the function (lines to remove):
  ```python
      if not all_misconfigs:
          yield _ev("http_clean", "  No HTTP misconfigurations detected")
      yield {"__misconfigs": all_misconfigs}
  ```

  New ending:
  ```python
      all_misconfigs.extend(parse_tls_misconfigs(services))
      all_misconfigs.extend(check_port_misconfigs(services))
      if not all_misconfigs:
          yield _ev("http_clean", "  No HTTP/TLS misconfigurations detected")
      yield {"__misconfigs": all_misconfigs}
  ```

  The `services` variable is already in scope (it's the parameter to `http_probe_events`).
  The reason for moving the `http_clean` message after the extends: if there are no HTTP
  misconfigs but there ARE TLS or port misconfigs, the "clean" message should not fire.

- [ ] **Step 6: Run the full server test suite to catch regressions**

  ```bash
  python -m pytest tests/server/ -v
  ```

  Expected: all existing tests pass. The `http_probe_events` tests in
  `tests/server/test_scan_helpers.py` only test `device_type_from_ports`, not
  `http_probe_events` directly, so no test updates needed for that file.

- [ ] **Step 7: Commit**

  ```bash
  git add aivas/scanner/nse.py tests/test_nse.py aivas/server/scan_helpers.py
  git commit -m "feat: add TLS NSE scripts and wire TLS/port misconfig checks into scan pipeline"
  ```

---

### Task 6: UDP Device Discovery

**Files:**
- Create: `aivas/scanner/udp_discover.py`
- Create: `tests/test_udp_discover.py`
- Modify: `aivas/server/scan_worker.py` (wire into network scan path)

**Interfaces:**
- Consumes: `hosts: list[str]` — IP addresses returned by `_ping_sweep`
- Produces:
  ```python
  async def udp_device_info(hosts: list[str], timeout: int = 25) -> dict[str, str]
  # Returns {ip: friendly_name} — empty dict on any failure (never raises)
  ```

- [ ] **Step 1: Write the failing tests**

  Create `tests/test_udp_discover.py`:

  ```python
  """Tests for UDP device discovery via nmap NSE (mDNS/SSDP)."""
  import asyncio
  from unittest.mock import patch, MagicMock, AsyncMock

  from aivas.scanner.udp_discover import udp_device_info

  # Minimal nmap XML with upnp-info output for one host
  _UPNP_XML = b"""<?xml version="1.0"?>
  <nmaprun>
    <host><status state="up"/>
      <address addr="192.168.1.10" addrtype="ipv4"/>
      <ports>
        <port protocol="udp" portid="1900">
          <state state="open|filtered"/>
          <script id="upnp-info" output="friendlyName: Samsung TV\n  manufacturer: Samsung"/>
        </port>
      </ports>
    </host>
  </nmaprun>"""

  _DNS_XML = b"""<?xml version="1.0"?>
  <nmaprun>
    <host><status state="up"/>
      <address addr="192.168.1.20" addrtype="ipv4"/>
      <ports>
        <port protocol="udp" portid="5353">
          <state state="open|filtered"/>
          <script id="dns-service-discovery" output="_workstation._tcp\n  Name: Baraka-MacBook"/>
        </port>
      </ports>
    </host>
  </nmaprun>"""


  def _make_proc(returncode: int, stdout: bytes, stderr: bytes = b"") -> MagicMock:
      proc = MagicMock()
      proc.returncode = returncode
      proc.communicate = AsyncMock(return_value=(stdout, stderr))
      proc.kill = MagicMock()
      proc.wait = AsyncMock()
      return proc


  def test_upnp_friendly_name_extracted():
      proc = _make_proc(0, _UPNP_XML)
      with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
          result = asyncio.run(udp_device_info(["192.168.1.10"]))
      assert result.get("192.168.1.10") == "Samsung TV"


  def test_dns_service_name_extracted():
      proc = _make_proc(0, _DNS_XML)
      with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
          result = asyncio.run(udp_device_info(["192.168.1.20"]))
      assert result.get("192.168.1.20") == "Baraka-MacBook"


  def test_nmap_failure_returns_empty_dict():
      proc = _make_proc(1, b"", b"requires root")
      with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
          result = asyncio.run(udp_device_info(["192.168.1.10"]))
      assert result == {}


  def test_empty_hosts_returns_immediately():
      result = asyncio.run(udp_device_info([]))
      assert result == {}


  def test_timeout_returns_empty_dict():
      async def hanging_communicate():
          await asyncio.sleep(999)
          return b"", b""

      proc = MagicMock()
      proc.communicate = hanging_communicate
      proc.kill = MagicMock()
      proc.wait = AsyncMock()

      with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
          result = asyncio.run(udp_device_info(["192.168.1.1"], timeout=1))
      assert result == {}


  def test_malformed_xml_returns_empty_dict():
      proc = _make_proc(0, b"not xml at all")
      with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
          result = asyncio.run(udp_device_info(["192.168.1.1"]))
      assert result == {}
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  python -m pytest tests/test_udp_discover.py -v
  ```

  Expected: all FAIL — module does not exist.

- [ ] **Step 3: Implement `udp_discover.py`**

  Create `aivas/scanner/udp_discover.py`:

  ```python
  """Async UDP device discovery using nmap NSE scripts for mDNS and SSDP.

  Runs a short nmap UDP scan against ports 5353 (mDNS) and 1900 (SSDP) on
  a list of IPs and extracts device friendly names from NSE output.

  Never raises — returns an empty dict on any failure so callers can proceed
  without device names.
  """
  from __future__ import annotations

  import asyncio
  import re
  import shutil

  from aivas.parser import parse_nmap_xml

  _FRIENDLY_NAME_RE = re.compile(r"friendlyName[:\s]+(.+)", re.IGNORECASE)
  _DNS_NAME_RE = re.compile(r"\bName[:\s]+(.+)", re.IGNORECASE)


  async def udp_device_info(hosts: list[str], timeout: int = 25) -> dict[str, str]:
      """Return {ip: friendly_name} for hosts that respond to mDNS/SSDP probes.

      Runs nmap -sU on ports 5353,1900 with dns-service-discovery and upnp-info
      NSE scripts. Requires root for UDP scanning; returns {} silently if not root
      or if nmap is unavailable.
      """
      if not hosts:
          return {}

      nmap_bin = shutil.which("nmap") or "nmap"
      cmd = [
          nmap_bin, "-sU", "-p", "5353,1900",
          "--script", "dns-service-discovery,upnp-info",
          "--host-timeout", "20s",
          "-oX", "-",
      ] + hosts

      try:
          proc = await asyncio.create_subprocess_exec(
              *cmd,
              stdout=asyncio.subprocess.PIPE,
              stderr=asyncio.subprocess.PIPE,
          )
          try:
              stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
          except (asyncio.TimeoutError, asyncio.CancelledError):
              try:
                  proc.kill()
                  await proc.wait()
              except Exception:
                  pass
              return {}
      except Exception:
          return {}

      if proc.returncode != 0:
          return {}

      try:
          services = parse_nmap_xml(stdout.decode())
      except Exception:
          return {}

      result: dict[str, str] = {}
      for svc in services:
          ip = svc.get("host", "")
          if not ip or ip in result:
              continue
          nse = svc.get("nse_results") or {}

          upnp = nse.get("upnp-info", "")
          m = _FRIENDLY_NAME_RE.search(upnp)
          if m:
              result[ip] = m.group(1).strip()
              continue

          dns = nse.get("dns-service-discovery", "")
          m = _DNS_NAME_RE.search(dns)
          if m:
              result[ip] = m.group(1).strip()

      return result
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  python -m pytest tests/test_udp_discover.py -v
  ```

  Expected: all 6 tests PASS.

- [ ] **Step 5: Wire UDP discovery into `scan_worker.py` network scan path**

  In `aivas/server/scan_worker.py`, in the `if is_net:` branch inside `run_scan`,
  after `live = await _ping_sweep(target)` and before the `if live:` block, add the
  UDP discover call.

  The existing code from `_ping_sweep` onwards currently looks like:

  ```python
          live = await _ping_sweep(target)
          if live:
              yield _emit(_ev("hosts_found", f"  ▸ {len(live)} live host(s) found:"))
              for h in live:
                  yield _emit(_ev("host_up", f"    · {h}"))
  ```

  Replace with:

  ```python
          live = await _ping_sweep(target)

          # UDP mDNS/SSDP device enrichment — non-blocking, root-only
          device_names: dict[str, str] = {}
          if live:
              try:
                  from aivas.scanner.udp_discover import udp_device_info
                  device_names = await asyncio.wait_for(
                      udp_device_info(live), timeout=30
                  )
              except Exception:
                  pass

          if live:
              yield _emit(_ev("hosts_found", f"  ▸ {len(live)} live host(s) found:"))
              for h in live:
                  name = device_names.get(h, "")
                  label = f"    · {h}" + (f" — {name}" if name else "")
                  yield _emit(_ev("host_up", label))
  ```

- [ ] **Step 6: Run the full test suite**

  ```bash
  python -m pytest tests/ -v --tb=short 2>&1 | tail -30
  ```

  Expected: all previously-passing tests still pass. Any pre-existing failure
  (`test_credential_scan_events.py::test_probe_error_yields_error_sentinel`) was
  present before this task — do not fix it here.

- [ ] **Step 7: Commit**

  ```bash
  git add aivas/scanner/udp_discover.py tests/test_udp_discover.py aivas/server/scan_worker.py
  git commit -m "feat: add UDP mDNS/SSDP device discovery with nmap NSE"
  ```

---

## Final Verification

After all 6 tasks:

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/ -v --tb=short 2>&1 | grep -E "PASSED|FAILED|ERROR" | wc -l
python -m pytest tests/ --tb=short 2>&1 | tail -5
```

The only pre-existing failure allowed is `test_probe_error_yields_error_sentinel`
(patches wrong function — tracked separately, not introduced by this work).
