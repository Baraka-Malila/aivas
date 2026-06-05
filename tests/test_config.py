import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aivas.cli import cli
from aivas.database.schema import create_schema
import aivas.config as _config


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def db(tmp_path):
    p = tmp_path / "aivas.db"
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    conn.close()
    return p


def invoke(runner, db, *args):
    return runner.invoke(cli, ["--db", str(db)] + list(args), catch_exceptions=False)


def test_config_set_and_show(runner, db, tmp_path):
    cfg_path = tmp_path / "config.yml"
    with patch.object(_config, "CONFIG_PATH", cfg_path):
        r = invoke(runner, db, "config", "set", "provider", "ollama")
        assert r.exit_code == 0
        assert "provider = ollama" in r.output

        r2 = invoke(runner, db, "config", "show")
        assert r2.exit_code == 0
        assert "provider" in r2.output


def test_config_set_unknown_key(runner, db):
    r = invoke(runner, db, "config", "set", "nonexistent_key", "val")
    assert r.exit_code != 0


def test_doctor_runs(runner, db):
    r = invoke(runner, db, "doctor")
    assert r.exit_code == 0
    assert "nmap" in r.output.lower() or "database" in r.output.lower()


def test_config_load_defaults():
    with patch.object(_config, "CONFIG_PATH", Path("/nonexistent/config.yml")):
        cfg = _config.load()
    assert cfg["provider"] == "groq"
    assert cfg["lang"] == "both"
    assert cfg["default_level"] == 2
