import json
import responses as resp_mock
import pytest
from aivas.database.nvd_sync import (
    get_last_sync,
    set_last_sync,
    sync_from_api,
)


def test_get_last_sync_returns_none_on_empty_db(db):
    assert get_last_sync(db) is None


def test_set_and_get_last_sync(db):
    set_last_sync(db, "2026-06-01T00:00:00Z")
    assert get_last_sync(db) == "2026-06-01T00:00:00Z"


def test_set_last_sync_overwrites_previous(db):
    set_last_sync(db, "2026-06-01T00:00:00Z")
    set_last_sync(db, "2026-06-04T12:00:00Z")
    assert get_last_sync(db) == "2026-06-04T12:00:00Z"


@resp_mock.activate
def test_sync_from_api_inserts_cves(db, sample_cve_data):
    api_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": sample_cve_data}],
    }
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=api_response,
        status=200,
    )

    count = sync_from_api(db)
    assert count == 1
    row = db.execute(
        "SELECT cve_id FROM cves WHERE cve_id = 'CVE-2021-41773'"
    ).fetchone()
    assert row is not None


@resp_mock.activate
def test_sync_from_api_updates_last_sync(db, sample_cve_data):
    api_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": sample_cve_data}],
    }
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=api_response,
        status=200,
    )

    sync_from_api(db)
    assert get_last_sync(db) is not None


@resp_mock.activate
def test_sync_from_api_handles_empty_response(db):
    api_response = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "vulnerabilities": [],
    }
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=api_response,
        status=200,
    )

    count = sync_from_api(db)
    assert count == 0


@resp_mock.activate
def test_sync_from_api_sends_api_key_header(db, sample_cve_data):
    api_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": sample_cve_data}],
    }
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=api_response,
        status=200,
    )

    sync_from_api(db, api_key="test-key-123")
    assert resp_mock.calls[0].request.headers.get("apiKey") == "test-key-123"
