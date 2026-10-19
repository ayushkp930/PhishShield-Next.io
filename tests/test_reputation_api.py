import asyncio

from fastapi.testclient import TestClient

from phishshield.web import app


def test_reputation_disabled_by_default(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_REPUTATION_ENABLED", "false")
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={"target": "https://example.com/", "confirm_external_sharing": True})
    assert response.status_code == 503


def test_reputation_requires_explicit_external_sharing_consent(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_REPUTATION_ENABLED", "true")
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={"target": "https://example.com/"})
    assert response.status_code == 400


def test_reputation_route_combines_local_report_with_mocked_provider_results(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_REPUTATION_ENABLED", "true")
    monkeypatch.setenv("PHISHSHIELD_DB_PATH", str(tmp_path / "history.sqlite3"))

    async def fake_lookup(_target):
        return {
            "target": "https://example.com/", "hostname": "example.com",
            "configured_provider_count": 1,
            "providers": {"virustotal": {"status": "ok", "summary": "Mock result"}},
            "whois": {"status": "ok", "summary": "Mock RDAP"},
            "limitations": ["Mock limitation"],
        }

    monkeypatch.setattr("phishshield.web.intel.lookup_reputation", fake_lookup)
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={"target": "https://example.com/", "confirm_external_sharing": True})
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "URL + THREAT INTEL"
    assert body["external_reputation"]["providers"]["virustotal"]["summary"] == "Mock result"
    assert body["risk_score"] >= 0


def test_whois_endpoint_is_disabled_by_default(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_WHOIS_ENABLED", "false")
    with TestClient(app) as client:
        response = client.post("/api/v1/whois", json={"target": "example.com"})
    assert response.status_code == 503


def test_whois_endpoint_uses_domain_only_result(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_WHOIS_ENABLED", "true")

    async def fake_whois(target):
        assert target == "example.com"
        return {"status": "ok", "target": "example.com", "summary": "Mock registration data", "nameservers": ["ns1.example.com"]}

    monkeypatch.setattr("phishshield.web.intel.lookup_whois_rdap", fake_whois)
    with TestClient(app) as client:
        response = client.post("/api/v1/whois", json={"target": "example.com"})
    assert response.status_code == 200
    assert response.json()["whois"]["nameservers"] == ["ns1.example.com"]
