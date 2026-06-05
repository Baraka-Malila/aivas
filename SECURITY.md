# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Send a report to: bmalila87@gmail.com

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Your AIVAS version (`aivas --version`) and OS

You will receive a response within 7 days. If the issue is confirmed, a fix will be prepared and a new release published before public disclosure.

## Scope

AIVAS is a local CLI tool intended for use on networks you own or have explicit authorisation to scan. The following are in scope for vulnerability reports:

- Command injection via user-supplied scan targets or config values
- Path traversal in report export paths
- SQL injection in database queries
- Insecure handling of API keys or credentials in config files or logs

Use of AIVAS against networks you do not own or have permission to scan is outside the scope of this policy and may be illegal.
