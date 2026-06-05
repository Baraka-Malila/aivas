from unittest.mock import patch, MagicMock
from click.testing import CliRunner
import pytest
from aivas.narrator.intent import parse_intent
from aivas.cli import cli


class MockProvider:
    def __init__(self, response):
        self._response = response

    def generate(self, prompt):
        return self._response


def test_parse_intent_extracts_target_and_level():
    prov = MockProvider('{"target": "192.168.1.1", "level": 2, "focus": "web"}')
    result = parse_intent("check 192.168.1.1", prov)
    assert result["target"] == "192.168.1.1"
    assert result["level"] == 2
    assert result["focus"] == "web"


def test_parse_intent_defaults_level_to_2():
    prov = MockProvider('{"target": "10.0.0.1", "focus": null}')
    result = parse_intent("scan 10.0.0.1", prov)
    assert result["level"] == 2


def test_parse_intent_raises_on_no_json():
    prov = MockProvider("I cannot parse that.")
    with pytest.raises(ValueError):
        parse_intent("something", prov)


def test_parse_intent_raises_when_no_target():
    prov = MockProvider('{"level": 2, "focus": "web"}')
    with pytest.raises(ValueError, match="target"):
        parse_intent("scan something", prov)


def test_ask_command_cancelled_by_user(db_path):
    runner = CliRunner()
    with patch("aivas.commands.ask_cmd.parse_intent") as mock_intent, \
         patch("aivas.commands.ask_cmd.get_provider") as mock_prov:
        mock_prov.return_value = MagicMock()
        mock_intent.return_value = {"target": "192.168.1.1", "level": 2, "focus": None}
        result = runner.invoke(
            cli,
            ["--db", str(db_path), "ask", "--api-key", "x", "scan 192.168.1.1"],
            input="n\n",
        )
    assert result.exit_code == 0
    assert "Scan cancelled" in result.output


EMPTY_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="192.168.1.1" addrtype="ipv4"/><ports/></host></nmaprun>"""


def test_ask_command_invokes_scan_on_confirm(db_path):
    runner = CliRunner()
    with patch("aivas.commands.ask_cmd.parse_intent") as mock_intent, \
         patch("aivas.commands.ask_cmd.get_provider") as mock_prov, \
         patch("aivas.commands.scan_cmd.shutil.which", return_value="/usr/bin/nmap"), \
         patch("aivas.commands.scan_cmd.run_scan", return_value=EMPTY_NMAP_XML) as mock_run_scan:
        mock_prov.return_value = MagicMock()
        mock_intent.return_value = {"target": "192.168.1.1", "level": 1, "focus": "web"}
        result = runner.invoke(
            cli,
            ["--db", str(db_path), "ask", "--api-key", "x", "check router"],
            input="y\n",
        )
    assert mock_run_scan.called
