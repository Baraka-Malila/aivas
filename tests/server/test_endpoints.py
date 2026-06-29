from aivas.history import save_scan
import aivas.server.main as _m


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_history_empty(client):
    r = client.get("/api/history")
    assert r.status_code == 200
    assert r.json() == []


def test_history_returns_scans(client, test_conn, monkeypatch):
    monkeypatch.setattr(_m, "_conn", test_conn)
    save_scan(test_conn, "192.168.1.1", [])
    r = client.get("/api/history?limit=5")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["target"] == "192.168.1.1"
    assert "grade" in data[0]
    assert "risk_score" in data[0]


def test_get_scan_not_found(client):
    r = client.get("/api/scan/9999")
    assert r.status_code == 404


from unittest.mock import AsyncMock, patch


def test_chat_no_scan_intent(client, test_conn, monkeypatch):
    monkeypatch.setattr(_m, "_conn", test_conn)
    with patch("aivas.server.chat_api.handle_chat",
               new=AsyncMock(return_value=("No AI configured.", None))):
        r = client.post("/api/chat", json={"text": "hello"})
    assert r.status_code == 200
    data = r.json()
    assert data["response"] == "No AI configured."
    assert data["scan_id"] is None


def test_chat_with_scan_intent(client, test_conn, monkeypatch):
    monkeypatch.setattr(_m, "_conn", test_conn)
    with patch("aivas.server.chat_api.handle_chat",
               new=AsyncMock(return_value=("Scanning now.", ("192.168.1.1", 2)))):
        r = client.post("/api/chat", json={"text": "scan 192.168.1.1"})
    assert r.status_code == 200
    data = r.json()
    assert data["scan_id"] is not None
    assert data["response"] == "Scanning now."


def test_get_scan_findings(client, test_conn, monkeypatch):
    monkeypatch.setattr(_m, "_conn", test_conn)
    findings = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0,
                 "cvss_severity": "CRITICAL", "confidence": "probable",
                 "host": "192.168.1.1"}]
    scan_id = save_scan(test_conn, "192.168.1.1", findings)
    r = client.get(f"/api/scan/{scan_id}")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2021-44228"
