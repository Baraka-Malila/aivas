from unittest.mock import patch
import pytest
from aivas.database.nvd_sync import (
    get_last_sync,
    set_last_sync,
    sync_from_api,
)


class MockCVE:
    """Minimal CVE object whose vars() returns the CVE data dict."""

    def __init__(self, data: dict):
        vars(self).update(data)


def test_get_last_sync_returns_none_on_empty_db(db):
    assert get_last_sync(db) is None


def test_set_and_get_last_sync(db):
    set_last_sync(db, "2026-06-01T00:00:00Z")
    assert get_last_sync(db) == "2026-06-01T00:00:00Z"


def test_set_last_sync_overwrites_previous(db):
    set_last_sync(db, "2026-06-01T00:00:00Z")
    set_last_sync(db, "2026-06-04T12:00:00Z")
    assert get_last_sync(db) == "2026-06-04T12:00:00Z"


def test_sync_from_api_inserts_cves(db, sample_cve_data):
    mock_cve = MockCVE(sample_cve_data)
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[mock_cve]):
        count = sync_from_api(db)
    assert count == 1
    row = db.execute(
        "SELECT cve_id FROM cves WHERE cve_id = 'CVE-2021-41773'"
    ).fetchone()
    assert row is not None


def test_sync_from_api_updates_last_sync(db, sample_cve_data):
    mock_cve = MockCVE(sample_cve_data)
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[mock_cve]):
        sync_from_api(db)
    assert get_last_sync(db) is not None


def test_sync_from_api_handles_empty_response(db):
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[]):
        count = sync_from_api(db)
    assert count == 0


def test_sync_from_api_passes_api_key(db, sample_cve_data):
    mock_cve = MockCVE(sample_cve_data)
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[mock_cve]) as mock_search:
        sync_from_api(db, api_key="test-key-123")
    call_kwargs = mock_search.call_args.kwargs
    assert call_kwargs.get("key") == "test-key-123"


def test_sync_from_api_passes_date_window_when_last_sync_set(db, sample_cve_data):
    set_last_sync(db, "2026-06-01T00:00:00Z")
    mock_cve = MockCVE(sample_cve_data)
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[mock_cve]) as mock_search:
        sync_from_api(db)
    call_kwargs = mock_search.call_args.kwargs
    assert call_kwargs.get("lastModStartDate") == "2026-06-01T00:00:00Z"
    assert "lastModEndDate" in call_kwargs


def test_sync_from_api_no_date_window_on_first_run(db):
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=[]) as mock_search:
        sync_from_api(db)
    call_kwargs = mock_search.call_args.kwargs
    assert "lastModStartDate" not in call_kwargs
    assert "lastModEndDate" not in call_kwargs


def test_sync_from_api_progress_callback(db, sample_cve_data):
    mock_cves = [MockCVE(sample_cve_data)]
    calls = []
    with patch("aivas.database.nvd_sync.nvdlib.searchCVE", return_value=mock_cves):
        sync_from_api(db, progress_callback=lambda done, total: calls.append((done, total)))
    assert calls == [(1, 1)]
