import asyncio

from phishshield import intel


def test_sensitive_query_detection_blocks_common_secrets():
    assert intel.has_sensitive_query("https://example.com/reset?token=abc")
    assert intel.has_sensitive_query("https://example.com/verify?access_token=abc")
    assert not intel.has_sensitive_query("https://example.com/login?campaign=spring")


def test_registered_domain_uses_common_multi_label_suffixes():
    assert intel.registrable_domain("login.shop.example.co.uk") == "example.co.uk"
    assert intel.registrable_domain("sub.example.com") == "example.com"


def test_virustotal_lookup_parses_report_without_submitting_scan(monkeypatch):
    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 10, "undetected": 20},
                "last_analysis_date": 123,
                "last_analysis_results": {"EngineA": {"category": "malicious", "result": "phishing"}}
            }}}

    async def fake_get_json(url, headers=None, params=None):
        assert url.startswith("https://www.virustotal.com/api/v3/urls/")
        assert headers == {"x-apikey": "test-key"}
        return FakeResponse(), FakeResponse().json()

    monkeypatch.setattr(intel, "_api_key", lambda name: "test-key" if name == "VIRUSTOTAL_API_KEY" else "")
    monkeypatch.setattr(intel, "_get_json", fake_get_json)
    result = asyncio.run(intel.check_virustotal("https://example.com/"))
    assert result["status"] == "threat_found"
    assert result["malicious"] == 2
    assert result["suspicious"] == 1
    assert result["detections"][0]["engine"] == "EngineA"


def test_provider_key_absence_is_clear_not_an_error(monkeypatch):
    monkeypatch.setattr(intel, "_api_key", lambda _name: "")
    result = asyncio.run(intel.check_webrisk("https://example.com/"))
    assert result["status"] == "not_configured"


def test_urlscan_is_historical_search_and_no_scan_submission(monkeypatch):
    class FakeResponse:
        status_code = 200
        def json(self):
            return {"total": 1, "results": [{"_id": "scan-id", "task": {"url": "https://example.com", "time": "today", "visibility": "public"}, "page": {"title": "Example"}, "verdicts": {"overall": {"malicious": False}}}]}

    async def fake_get_json(url, headers=None, params=None):
        assert url == "https://urlscan.io/api/v1/search/"
        assert params["q"] == "domain:example.com"
        assert headers == {"API-Key": "test-key"}
        return FakeResponse(), FakeResponse().json()

    monkeypatch.setattr(intel, "_api_key", lambda name: "test-key" if name == "URLSCAN_API_KEY" else "")
    monkeypatch.setattr(intel, "_get_json", fake_get_json)
    result = asyncio.run(intel.check_urlscan("example.com"))
    assert result["status"] == "record_found"
    assert result["count"] == 1
    assert "no new scan was submitted" in result["summary"]


def test_webrisk_reports_threat_list_match(monkeypatch):
    class FakeResponse:
        status_code = 200
        def json(self):
            return {"threat": {"threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"], "expireTime": "2030-01-01T00:00:00Z"}}

    async def fake_get_json(url, headers=None, params=None):
        assert url.endswith("/v1/uris:search")
        assert params["uri"] == "https://example.com/"
        assert "SOCIAL_ENGINEERING" in params["threatTypes"]
        return FakeResponse(), FakeResponse().json()

    monkeypatch.setattr(intel, "_api_key", lambda name: "test-key" if name == "GOOGLE_WEB_RISK_API_KEY" else "")
    monkeypatch.setattr(intel, "_get_json", fake_get_json)
    result = asyncio.run(intel.check_webrisk("https://example.com/"))
    assert result["status"] == "threat_found"
    assert "MALWARE" in result["threat_types"]


def test_abuseipdb_uses_only_resolved_public_ip(monkeypatch):
    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 72, "totalReports": 19, "numDistinctUsers": 9, "countryCode": "US"}}

    async def fake_resolve(_hostname):
        return "8.8.8.8"

    async def fake_get_json(url, headers=None, params=None):
        assert url == "https://api.abuseipdb.com/api/v2/check"
        assert headers["Key"] == "test-key"
        assert params["ipAddress"] == "8.8.8.8"
        assert "example.com" not in str(params)
        return FakeResponse(), FakeResponse().json()

    monkeypatch.setattr(intel, "_api_key", lambda name: "test-key" if name == "ABUSEIPDB_API_KEY" else "")
    monkeypatch.setattr(intel, "_resolve_public_ip", fake_resolve)
    monkeypatch.setattr(intel, "_get_json", fake_get_json)
    result = asyncio.run(intel.check_abuseipdb("example.com"))
    assert result["status"] == "threat_found"
    assert result["abuse_confidence_score"] == 72
    assert result["total_reports"] == 19


def test_whois_rdap_parses_registration_events_and_registrar(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "https://rdap.example-registry.test/domain/example.com"
        def json(self):
            return {
                "ldhName": "EXAMPLE.COM",
                "events": [
                    {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                ],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "status": ["client transfer prohibited"],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            }

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is True
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url):
            assert url == "https://rdap.org/domain/example.com"
            return FakeResponse()

    monkeypatch.setattr(intel.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(intel.lookup_whois_rdap("https://login.example.com/account"))
    assert result["status"] == "record_found"
    assert result["registrar"] == "Example Registrar"
    assert result["created_at"] == "2000-01-01T00:00:00Z"
    assert result["expires_at"] == "2030-01-01T00:00:00Z"
    assert result["nameservers"] == ["ns1.example.com"]


def test_external_reputation_rejects_non_public_targets(monkeypatch):
    import pytest
    with pytest.raises(ValueError, match="private"):
        asyncio.run(intel.lookup_reputation("http://192.168.1.10/login"))
    with pytest.raises(ValueError, match="local/internal"):
        asyncio.run(intel.lookup_reputation("http://service.internal/login"))
