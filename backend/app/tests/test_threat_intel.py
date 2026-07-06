"""
Unit tests for the threat intel client. Unlike test_detection.py, these
don't need the real database or a real AbuseIPDB key -- they mock the one
network call and check the three behaviors that matter most for a piece of
code sitting between our app and a flaky third-party API: no key -> skip,
cache hit -> no second call, HTTP failure -> skip (never raise).
"""

import httpx
import pytest

from app.services import threat_intel


@pytest.fixture(autouse=True)
def _clear_cache_and_env(monkeypatch):
    threat_intel._cache.clear()
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    yield
    threat_intel._cache.clear()


def test_returns_none_without_api_key():
    assert threat_intel.get_ip_reputation("203.0.113.5") is None


def test_returns_reputation_dict_on_success(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "abuseConfidenceScore": 87,
                    "countryCode": "RU",
                    "isp": "Example ISP",
                    "domain": "example.net",
                    "totalReports": 42,
                    "lastReportedAt": "2026-07-01T00:00:00+00:00",
                }
            }

    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse())

    result = threat_intel.get_ip_reputation("203.0.113.5")
    assert result["abuse_score"] == 87
    assert result["country"] == "RU"
    assert result["total_reports"] == 42


def test_cache_avoids_second_http_call(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")
    call_count = {"n": 0}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            call_count["n"] += 1
            return {"data": {"abuseConfidenceScore": 10}}

    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse())

    first = threat_intel.get_ip_reputation("198.51.100.1")
    second = threat_intel.get_ip_reputation("198.51.100.1")

    assert first == second
    assert call_count["n"] == 1, "second lookup for the same IP should hit the cache, not the network"


def test_network_error_returns_none_instead_of_raising(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key-for-test")

    def _raise(*args, **kwargs):
        raise httpx.ConnectTimeout("simulated timeout")

    monkeypatch.setattr(httpx, "get", _raise)

    assert threat_intel.get_ip_reputation("203.0.113.9") is None
