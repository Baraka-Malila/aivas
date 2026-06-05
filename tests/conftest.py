import sqlite3
import pytest
from aivas.database.schema import create_schema


@pytest.fixture
def db_path(tmp_path):
    """Return a path to a temporary SQLite database (for CLI --db option)."""
    return tmp_path / "test.db"


@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def sample_cve_data():
    return {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T09:15:00.000",
        "lastModified": "2021-10-08T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "A flaw was found in path traversal in Apache HTTP Server 2.4.49."}
        ],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                }
            }]
        },
        "weaknesses": [
            {"type": "Primary", "description": [{"lang": "en", "value": "CWE-22"}]}
        ],
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.4.49",
                    "versionEndIncluding": "2.4.49",
                }]
            }]
        }]
    }


@pytest.fixture
def sample_cve_range_data():
    """CVE affecting a version range, not a single exact version."""
    return {
        "id": "CVE-2018-15473",
        "published": "2018-08-17T00:00:00.000",
        "lastModified": "2018-09-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "OpenSSH through 7.7 is prone to user enumeration."}
        ],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 5.3,
                    "baseSeverity": "MEDIUM",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "attackVector": "NETWORK",
                }
            }]
        },
        "weaknesses": [],
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "7.7",
                }]
            }]
        }]
    }


@pytest.fixture
def sample_nmap_xml():
    return """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
        <script id="ssh-auth-methods" output="publickey,password"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <script id="http-shellshock" output="VULNERABLE: Shellshock"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
