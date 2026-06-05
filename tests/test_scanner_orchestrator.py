from unittest.mock import patch, MagicMock
import pytest
from aivas.scanner.orchestrator import run_scan
from aivas.scanner.nse import QUICK_SCRIPTS, FULL_SCRIPTS


def test_nse_script_sets_are_strings():
    assert isinstance(QUICK_SCRIPTS, str)
    assert isinstance(FULL_SCRIPTS, str)
    assert "," in FULL_SCRIPTS


def test_run_scan_returns_xml_string():
    fake_xml = b"<?xml version='1.0'?><nmaprun></nmaprun>"
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_xml, stderr=b"")
            result = run_scan("192.168.1.0/24", scripts=QUICK_SCRIPTS)
    assert isinstance(result, str)
    assert "nmaprun" in result


def test_run_scan_raises_on_nmap_missing():
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="nmap not found"):
            run_scan("192.168.1.1")


def test_run_scan_raises_on_nonzero_exit():
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"error")
            with pytest.raises(RuntimeError, match="nmap exited"):
                run_scan("192.168.1.1")


def test_run_scan_timeout_passed_to_subprocess():
    fake_xml = b"<nmaprun></nmaprun>"
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_xml, stderr=b"")
            run_scan("10.0.0.1", timeout=120)
            _, kwargs = mock_run.call_args
            assert kwargs["timeout"] == 120
