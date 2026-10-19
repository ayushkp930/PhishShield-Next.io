from phishshield.analyzer import analyze_url, analyze_email_text
import pytest

def test_url_normalization_and_shape():
    r=analyze_url("example.com/login")
    assert r["hostname"] == "example.com"
    assert 0 <= r["risk_score"] <= 100
    assert r["verdict"] in {"INCONCLUSIVE", "SUSPICIOUS", "HIGH RISK"}

def test_userinfo_flag():
    r=analyze_url("https://paypal.com@evil.example/login")
    assert any(s["id"] == "userinfo" for s in r["signals"])

def test_empty_rejected():
    with pytest.raises(ValueError): analyze_url(" ")

def test_email_extracts_urls():
    r=analyze_email_text("From: a@example.com\nhttps://example.org/login")
    assert "https://example.org/login" in r["urls"]

def test_email_flags_reply_to_mismatch_and_urgency():
    raw = (
        "From: Security <notice@company.example>\n"
        "Reply-To: attacker@evil.example\n"
        "Subject: URGENT action required\n"
        "\nPlease verify your account immediately and provide your password."
    )
    r = analyze_email_text(raw)
    assert r["verdict"] in {"SUSPICIOUS", "HIGH RISK"}
    assert any(s["id"] == "reply-mismatch" for s in r["signals"])
    assert any(s["id"] == "credential-request" for s in r["signals"])
    assert r["risk_score"] >= 30


def test_email_inspects_attachment_metadata_without_extracting_payload():
    raw = (
        "From: alerts@example.com\n"
        "Subject: Invoice attached\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=demo\n\n"
        "--demo\nContent-Type: text/plain\n\nPlease see invoice.\n"
        "--demo\nContent-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=invoice.xlsm\n\n"
        "not-a-real-binary-payload\n--demo--\n"
    )
    r = analyze_email_text(raw)
    assert "invoice.xlsm" in r["attachment_names"]
    assert "invoice.xlsm" in r["risky_attachment_names"]
    assert any(s["id"] == "risky-attachment" for s in r["signals"])
