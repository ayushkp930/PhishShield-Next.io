import asyncio

from phishshield import technical


def test_dns_lookup_parses_a_spf_and_dmarc_records(monkeypatch):
    class FakeResponse:
        status_code = 200
        def __init__(self, record_type, name):
            self.record_type, self.name = record_type, name
        def json(self):
            if self.record_type == "A":
                return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34", "TTL": 300}]}
            if self.record_type == "TXT" and self.name.startswith("_dmarc."):
                return {"Status": 0, "Answer": [{"type": 16, "data": '"v=DMARC1; p=reject"', "TTL": 300}]}
            if self.record_type == "TXT":
                return {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 -all"', "TTL": 300}]}
            return {"Status": 0, "Answer": []}

    class FakeClient:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, params=None, headers=None):
            return FakeResponse(params["type"], params["name"])

    monkeypatch.setattr(technical.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(technical.lookup_dns_records("https://example.com/"))
    assert result["records"]["A"]["records"] == ["93.184.216.34"]
    assert result["email_auth_summary"]["spf_records"] == ["v=spf1 -all"]
    assert result["email_auth_summary"]["dmarc_records"] == ["v=DMARC1; p=reject"]


def test_certificate_transparency_parses_bounded_metadata(monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b"[{\"id\":12}]"
        def json(self):
            return [{"id": 12, "entry_timestamp": "2026-01-01T00:00:00Z", "not_before": "2025-01-01T00:00:00Z", "not_after": "2026-01-01T00:00:00Z", "common_name": "example.com", "name_value": "example.com\nwww.example.com", "issuer_name": "Example CA"}]

    class FakeClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, params=None):
            assert url == "https://crt.sh/"
            assert params["output"] == "json"
            assert "example.com" in params["q"]
            return FakeResponse()

    monkeypatch.setattr(technical.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(technical.lookup_certificate_transparency("example.com"))
    assert result["status"] == "record_found"
    assert result["entries"][0]["common_name"] == "example.com"
    assert result["entries"][0]["issuer_name"] == "Example CA"


def test_http_target_does_not_attempt_tls_handshake():
    result = asyncio.run(technical.lookup_tls_certificate("http://example.com/"))
    assert result["status"] == "not_https"
    assert result["certificate_verified"] is False


def test_inspect_network_metadata_returns_all_three_modules(monkeypatch):
    async def fake_dns(_target):
        return {"status": "record_found", "records": {"A": {"records": ["93.184.216.34"]}}}
    async def fake_tls(_target):
        return {"status": "certificate_verified", "certificate_verified": True}
    async def fake_ct(_target):
        return {"status": "record_found", "entries": [{"id": "1"}]}
    monkeypatch.setattr(technical, "lookup_dns_records", fake_dns)
    monkeypatch.setattr(technical, "lookup_tls_certificate", fake_tls)
    monkeypatch.setattr(technical, "lookup_certificate_transparency", fake_ct)
    result = asyncio.run(technical.inspect_network_metadata("https://example.com/"))
    assert result["dns"]["status"] == "record_found"
    assert result["tls"]["status"] == "certificate_verified"
    assert result["certificate_transparency"]["status"] == "record_found"
