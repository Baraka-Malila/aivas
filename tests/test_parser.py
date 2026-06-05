from aivas.parser import parse_nmap_xml


def test_parse_returns_list(sample_nmap_xml):
    services = parse_nmap_xml(sample_nmap_xml)
    assert isinstance(services, list)
    assert len(services) == 3


def test_service_fields(sample_nmap_xml):
    services = parse_nmap_xml(sample_nmap_xml)
    svc = services[0]
    assert svc["host"] == "192.168.1.10"
    assert svc["port"] == 80
    assert svc["protocol"] == "tcp"
    assert svc["service"] == "http"
    assert svc["product"] == "Apache httpd"
    assert svc["version"] == "2.4.49"
    assert svc["nse_results"] == {}


def test_nse_results_captured(sample_nmap_xml):
    services = parse_nmap_xml(sample_nmap_xml)
    ssh_svc = next(s for s in services if s["port"] == 22)
    assert "ssh-auth-methods" in ssh_svc["nse_results"]
    shellshock_svc = next(
        s for s in services if "http-shellshock" in s["nse_results"]
    )
    assert "VULNERABLE" in shellshock_svc["nse_results"]["http-shellshock"]


def test_missing_version_defaults_to_empty(sample_nmap_xml):
    xml = sample_nmap_xml.replace(' version="2.4.49"', "", 1)
    services = parse_nmap_xml(xml)
    apache = next(s for s in services if s["service"] == "http" and s["nse_results"] == {})
    assert apache["version"] == ""


def test_empty_xml_returns_empty_list():
    assert parse_nmap_xml("<nmaprun></nmaprun>") == []


def test_closed_ports_excluded():
    xml = """<nmaprun>
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
            <service name="https" product="nginx" version="1.18"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    assert parse_nmap_xml(xml) == []
