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
