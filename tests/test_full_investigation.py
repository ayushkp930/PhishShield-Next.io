from fastapi.testclient import TestClient

from phishshield.web import app


def _clear_rates(monkeypatch):
    from phishshield import web
    web._full_rate_events.clear()
    web._rate_events.clear()
    web._reputation_rate_events.clear()
    web._whois_rate_events.clear()


def test_full_investigation_returns_clear_statuses_when_modules_not_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_DB_PATH", str(tmp_path / "cases.sqlite3"))
    for key in ("PHISHSHIELD_NETWORK_METADATA_ENABLED", "PHISHSHIELD_INSPECT_ENABLED", "PHISHSHIELD_REPUTATION_ENABLED", "PHISHSHIELD_WHOIS_ENABLED"):
        monkeypatch.setenv(key, "false")
    _clear_rates(monkeypatch)
    with TestClient(app) as client:
        response = client.post("/api/v1/investigate", json={"url": "https://example.com/"})
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "FULL URL INVESTIGATION"
    assert body["external_reputation"]["status"] == "not_requested"
    assert body["technical"]["dns"]["status"] == "not_requested"
    assert body["whois_lookup"]["status"] == "not_requested"
    module_names = {x["name"] for x in body["investigation_modules"]}
    assert {"local_heuristics", "dns_tls", "certificate_transparency", "whois_rdap"} <= module_names


def test_full_investigation_requires_external_sharing_consent(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_DB_PATH", str(tmp_path / "cases.sqlite3"))
    _clear_rates(monkeypatch)
    with TestClient(app) as client:
        response = client.post("/api/v1/investigate", json={
            "url": "https://example.com/", "include_external_reputation": True,
            "confirm_external_sharing": False,
        })
    assert response.status_code == 400
    assert "external data sharing" in response.json()["detail"]


def test_full_investigation_merges_dns_ct_rdap_provider_and_crawl_evidence(tmp_path, monkeypatch):
    from phishshield import web

    monkeypatch.setenv("PHISHSHIELD_DB_PATH", str(tmp_path / "cases.sqlite3"))
    for key in ("PHISHSHIELD_NETWORK_METADATA_ENABLED", "PHISHSHIELD_INSPECT_ENABLED", "PHISHSHIELD_REPUTATION_ENABLED", "PHISHSHIELD_WHOIS_ENABLED"):
        monkeypatch.setenv(key, "true")
    _clear_rates(monkeypatch)

    async def fake_metadata(_target):
        return {
            "dns": {"status": "record_found", "hostname": "example.com", "records": {"A": {"status": "record_found", "records": ["93.184.216.34"]}}, "limitations": []},
            "tls": {"status": "certificate_verified", "certificate_verified": True, "subject": "CN=example.com", "limitations": []},
            "certificate_transparency": {"status": "record_found", "summary": "mock CT hit", "entries": [{"id": "ct-1", "common_name": "example.com"}]},
        }

    async def fake_whois(_target):
        return {"status": "record_found", "target": "example.com", "summary": "mock RDAP", "registrar": "Example Registrar", "nameservers": ["ns1.example.com"]}

    async def fake_reputation(_target, **kwargs):
        return {
            "status": "ok", "configured_provider_count": 4,
            "providers": {
                "virustotal": {"status": "threat_found", "malicious": 1, "suspicious": 0, "summary": "1 engine marked malicious", "all_engine_results": [{"engine": "TestEngine", "category": "malicious"}]},
                "google_webrisk": {"status": "no_match", "threat_types": [], "summary": "no match"},
                "urlscan": {"status": "record_found", "count": 2, "results": [], "new_scan": {"status": "not_requested"}, "summary": "historical results"},
                "abuseipdb": {"status": "record_found", "abuse_confidence_score": 10, "summary": "low score"},
            },
            "limitations": [],
        }

    async def fake_inspector(url, max_pages=5):
        return {
            "id": "live-test", "created_at": "2026-10-19T00:00:00Z", "type": "LIVE INSPECTION",
            "input": url, "normalized_url": url, "hostname": "example.com", "verdict": "INCONCLUSIVE",
            "risk_score": 0, "signals": [], "inspection": {
                "pages": [{"url": url, "status": 200, "title": "Example", "findings": [], "links": [], "external_links": ["https://other.example/"], "external_resources": ["https://cdn.example/script.js"]}],
                "redirect_chain": [], "errors": [], "tls_validated": True, "max_pages": max_pages,
            },
        }

    monkeypatch.setattr(web, "inspect_network_metadata", fake_metadata)
    monkeypatch.setattr(web.intel, "lookup_whois_rdap", fake_whois)
    monkeypatch.setattr(web.intel, "lookup_reputation", fake_reputation)
    monkeypatch.setattr(web, "inspect_public_site", fake_inspector)
    with TestClient(app) as client:
        response = client.post("/api/v1/investigate", json={
            "url": "https://example.com/", "max_pages": 3,
            "confirm_network_checks": True, "include_live_inspection": True, "confirm_live_crawl": True,
            "include_external_reputation": True, "confirm_external_sharing": True,
        })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] >= 95
    assert body["external_reputation"]["providers"]["virustotal"]["malicious"] == 1
    assert body["whois_lookup"]["registrar"] == "Example Registrar"
    assert body["technical"]["certificate_transparency"]["entries"][0]["id"] == "ct-1"
    assert body["live_inspection"]["pages"][0]["title"] == "Example"
    assert body["coverage_summary"]["pages_inspected"] == 1
    assert body["coverage_summary"]["live_external_resources_observed"] == 1


def test_reputation_requires_explicit_urlscan_submission_consent(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_REPUTATION_ENABLED", "true")
    _clear_rates(monkeypatch)
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={
            "target": "https://example.com/", "confirm_external_sharing": True,
            "submit_urlscan_private": True, "confirm_urlscan_submission": False,
        })
    assert response.status_code == 400
    assert "private URLScan scan" in response.json()["detail"]
