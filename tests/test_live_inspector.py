import os

import pytest
from fastapi.testclient import TestClient

from phishshield.live_inspector import UnsafeTarget, validate_target
from phishshield.web import app

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://192.168.1.1/",
    "http://10.0.0.4/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://service.internal/",
    "http://example.test/",
    "http://example.com:8080/",
    "http://example.com:0/",
    "https://example.com:65535/",
    "ftp://example.com/",
    "https://user:pass@example.com/",
])
def test_live_inspector_rejects_unsafe_targets(url):
    with pytest.raises(UnsafeTarget):
        validate_target(url)


def test_live_inspector_normalizes_https_and_strips_fragment():
    assert validate_target("example.com/login#section") == "https://example.com/login"


def test_static_ui_served_from_backend():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "PhishShield Next" in response.text
        assert "Run full investigation" in response.text
        assert "WHOIS / RDAP" in response.text
        assert "Certificate transparency history" in response.text or "certificate-transparency" in response.text.lower()
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/health").json()["version"] == "3.2.0"


def test_live_inspection_disabled_when_env_not_enabled(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_INSPECT_ENABLED", "false")
    with TestClient(app) as client:
        response = client.post("/api/v1/inspect", json={"url": "http://127.0.0.1/", "max_pages": 1})
        assert response.status_code == 503


def test_api_url_scan_and_report_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_DB_PATH", str(tmp_path / "case-history.sqlite3"))
    with TestClient(app) as client:
        response = client.post("/api/v1/scan", json={"url": "https://secure-login-paypal.account-check.click/verify"})
        assert response.status_code == 200
        report = response.json()
        assert report["verdict"] in {"SUSPICIOUS", "HIGH RISK"}
        assert report["signals"]
        stored = client.get(f"/api/v1/scan/{report['id']}")
        assert stored.status_code == 200
        assert stored.json()["input"] == report["input"]
        assert client.get(f"/report/{report['id']}.json").status_code == 200


def test_api_email_analyzer_returns_scored_findings():
    raw = "From: alerts@company.example\nReply-To: attacker@evil.example\nSubject: URGENT verify your account\n\nPlease enter your password immediately."
    with TestClient(app) as client:
        response = client.post("/api/v1/email-analyze", json={"text": raw})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] in {"SUSPICIOUS", "HIGH RISK"}
    assert any(s["id"] == "reply-mismatch" for s in body["signals"])


def test_live_inspection_blocks_sensitive_query_parameters(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_INSPECT_ENABLED", "true")
    from phishshield import web
    web._rate_events.clear()
    with TestClient(app) as client:
        response = client.post("/api/v1/inspect", json={"url": "https://example.com/reset?token=secret", "max_pages": 1})
    assert response.status_code == 422
    assert "sensitive query" in response.json()["detail"]
