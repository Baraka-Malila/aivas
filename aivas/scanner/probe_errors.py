"""Shared exception types for remote probe modules (SSH, WinRM)."""


class CredentialError(Exception):
    """Authentication failed — wrong username, password, or key rejected."""


class ConnectionError(Exception):
    """Cannot reach the target host on the given port."""


class ProbeError(Exception):
    """Any other probe failure: command error, timeout, missing dependency."""
