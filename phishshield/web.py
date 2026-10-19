from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import store
from .analyzer import analyze_email_text, analyze_url
from .live_inspector import UnsafeTarget, inspect_public_site, score_inspection_result
from . import intel
from .technical import inspect_network_metadata

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
if not (DOCS / "index.html").is_file():
    DOCS = Path(__file__).resolve().parent / "static_site"
app = FastAPI(
    title="PhishShield Next API",
    description="Defensive phishing triage. Heuristic analysis is not a safety verdict.",
    version="3.2.0",
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/assets", StaticFiles(directory=DOCS / "assets"), name="assets")

allowed_origins = [x.strip() for x in os.getenv("PHISHSHIELD_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)

class EmailRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)

class InspectRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    max_pages: int = Field(default=3, ge=1, le=10)

class ReputationRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    confirm_external_sharing: bool = False
    submit_virustotal_if_missing: bool = False
    confirm_virustotal_submission: bool = False
    submit_urlscan_private: bool = False
    confirm_urlscan_submission: bool = False

class WhoisRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)

class InvestigationRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    max_pages: int = Field(default=5, ge=1, le=10)
    confirm_network_checks: bool = False
    include_live_inspection: bool = False
    confirm_live_crawl: bool = False
    include_external_reputation: bool = False
    confirm_external_sharing: bool = False
    submit_virustotal_if_missing: bool = False
    confirm_virustotal_submission: bool = False
    submit_urlscan_private: bool = False
    confirm_urlscan_submission: bool = False

# Per-process emergency backstop. Public deployments must ALSO use a gateway/WAF,
# authentication or challenge, and persistent rate limiting; this is not distributed.
_RATE_WINDOW = int(os.getenv("PHISHSHIELD_INSPECT_WINDOW_SECONDS", "600"))
_RATE_LIMIT = int(os.getenv("PHISHSHIELD_INSPECT_LIMIT", "8"))
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_inspect_semaphore = asyncio.Semaphore(2)
_REPUTATION_RATE_WINDOW = int(os.getenv("PHISHSHIELD_REPUTATION_WINDOW_SECONDS", "600"))
_REPUTATION_RATE_LIMIT = int(os.getenv("PHISHSHIELD_REPUTATION_LIMIT", "6"))
_WHOIS_RATE_WINDOW = int(os.getenv("PHISHSHIELD_WHOIS_WINDOW_SECONDS", "600"))
_WHOIS_RATE_LIMIT = int(os.getenv("PHISHSHIELD_WHOIS_LIMIT", "15"))
_FULL_RATE_WINDOW = int(os.getenv("PHISHSHIELD_FULL_WINDOW_SECONDS", "600"))
_FULL_RATE_LIMIT = int(os.getenv("PHISHSHIELD_FULL_LIMIT", "3"))
_reputation_rate_events: dict[str, deque[float]] = defaultdict(deque)
_whois_rate_events: dict[str, deque[float]] = defaultdict(deque)
_full_rate_events: dict[str, deque[float]] = defaultdict(deque)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    return response

def _check_service_rate(request: Request, events: dict[str, deque[float]], limit: int, window: int, service_name: str):
    peer = request.client.host if request.client else "unknown"
    now = time.monotonic()
    history = events[peer]
    while history and now - history[0] > window:
        history.popleft()
    if len(history) >= limit:
        wait = max(1, int(window - (now - history[0])))
        raise HTTPException(status_code=429, detail=f"{service_name} rate limit reached. Try again in about {wait} seconds.", headers={"Retry-After": str(wait)})
    history.append(now)

def _check_inspect_rate(request: Request):
    peer = request.client.host if request.client else "unknown"
    now = time.monotonic()
    history = _rate_events[peer]
    while history and now - history[0] > _RATE_WINDOW:
        history.popleft()
    if len(history) >= _RATE_LIMIT:
        wait = max(1, int(_RATE_WINDOW - (now - history[0])))
        raise HTTPException(status_code=429, detail=f"Inspection rate limit reached. Try again in about {wait} seconds.", headers={"Retry-After": str(wait)})
    history.append(now)

@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(DOCS / "index.html", media_type="text/html")

@app.get("/health")
async def health():
    return {
        "status": "ok", "version": "3.2.0",
        "mode": "local heuristics, public DNS/TLS metadata, opt-in reputation providers, RDAP and bounded same-origin crawling",
        "api_docs": "/api/docs",
        "features": {
            "reputation_lookup_enabled": os.getenv("PHISHSHIELD_REPUTATION_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
            "whois_enabled": os.getenv("PHISHSHIELD_WHOIS_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
            "live_inspection_enabled": os.getenv("PHISHSHIELD_INSPECT_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
            "network_metadata_enabled": os.getenv("PHISHSHIELD_NETWORK_METADATA_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
        },
        "providers_configured": {
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip()),
            "urlscan": bool(os.getenv("URLSCAN_API_KEY", "").strip()),
            "google_webrisk": bool(os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()),
            "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()),
            "whois_rdap": True,
        },
    }

@app.post("/api/v1/scan")
async def api_scan(payload: URLRequest):
    try:
        result = analyze_url(payload.url)
        store.save(result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/email-analyze")
async def api_email(payload: EmailRequest):
    try:
        return analyze_email_text(payload.text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/reputation")
async def api_reputation(payload: ReputationRequest, request: Request):
    if os.getenv("PHISHSHIELD_REPUTATION_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=503, detail="External reputation lookups are disabled on this deployment. Configure provider secrets and enable them only after adding public-service abuse controls.")
    if not payload.confirm_external_sharing:
        raise HTTPException(status_code=400, detail="Explicit consent is required before sharing this indicator with external reputation providers.")
    if payload.submit_virustotal_if_missing and not payload.confirm_virustotal_submission:
        raise HTTPException(status_code=400, detail="Explicit consent is required before submitting a new URL to VirusTotal.")
    if payload.submit_urlscan_private and not payload.confirm_urlscan_submission:
        raise HTTPException(status_code=400, detail="Explicit consent is required before submitting a fresh private URLScan scan.")
    if (payload.submit_virustotal_if_missing or payload.submit_urlscan_private) and not payload.confirm_external_sharing:
        raise HTTPException(status_code=400, detail="External sharing consent is required for fresh provider submissions.")
    _check_service_rate(request, _reputation_rate_events, _REPUTATION_RATE_LIMIT, _REPUTATION_RATE_WINDOW, "Reputation lookup")
    try:
        enrichment = await asyncio.wait_for(
            intel.lookup_reputation(
                payload.target,
                submit_unknown_to_virustotal=payload.submit_virustotal_if_missing,
                submit_urlscan_private=payload.submit_urlscan_private,
                include_whois=os.getenv("PHISHSHIELD_WHOIS_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
            ),
            timeout=35,
        )
        base = analyze_url(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Reputation lookup time budget exceeded. Retry later.") from exc
    base["type"] = "URL + THREAT INTEL"
    base["external_reputation"] = enrichment
    base["limitations"] = list(base.get("limitations", [])) + list(enrichment.get("limitations", []))
    store.save(base)
    return base

@app.post("/api/v1/whois")
async def api_whois(payload: WhoisRequest, request: Request):
    if os.getenv("PHISHSHIELD_WHOIS_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=503, detail="WHOIS/RDAP lookup is disabled on this deployment. Enable it only after configuring service rate limits.")
    _check_service_rate(request, _whois_rate_events, _WHOIS_RATE_LIMIT, _WHOIS_RATE_WINDOW, "WHOIS/RDAP lookup")
    try:
        result = await asyncio.wait_for(intel.lookup_whois_rdap(payload.target), timeout=12)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="WHOIS/RDAP lookup time budget exceeded. Retry later.") from exc
    return {"created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "target": payload.target, "whois": result}

@app.post("/api/v1/inspect")
async def api_inspect(payload: InspectRequest, request: Request):
    if os.getenv("PHISHSHIELD_INSPECT_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=503, detail="Live inspection is disabled on this deployment. Enable it only after adding public-service abuse controls.")
    _check_inspect_rate(request)
    if intel.has_sensitive_query(payload.url):
        raise HTTPException(status_code=422, detail="Live inspection is blocked for URLs with token/session/reset/invite-like query keys. Remove sensitive query parameters before retrying.")
    if _inspect_semaphore.locked():
        raise HTTPException(status_code=503, detail="Inspector is busy. Please retry shortly.")
    async with _inspect_semaphore:
        try:
            result = await asyncio.wait_for(inspect_public_site(payload.url, payload.max_pages), timeout=65)
        except UnsafeTarget as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=504, detail="Inspection time budget exceeded. Try a smaller page budget or retry later.") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            # Do not leak upstream error details, URLs embedded in exceptions, or internal network data.
            raise HTTPException(status_code=502, detail=f"Inspection failed ({type(exc).__name__}).") from exc
    result = score_inspection_result(result)
    store.save(result)
    return result


def _flag(name: str) -> bool:
    return os.getenv(name, "false").lower() in {"1", "true", "yes", "on"}


def _status_module(name: str, status: str, summary: str, **extra) -> dict:
    return {"name": name, "status": status, "summary": summary, **extra}


@app.post("/api/v1/investigate")
async def api_full_investigation(payload: InvestigationRequest, request: Request):
    """Collect a single combined report from local, network, page and reputation sources."""
    _check_service_rate(request, _full_rate_events, _FULL_RATE_LIMIT, _FULL_RATE_WINDOW, "Full investigation")
    if payload.include_external_reputation and not payload.confirm_external_sharing:
        raise HTTPException(status_code=400, detail="Confirm external data sharing before querying reputation providers.")
    if payload.submit_virustotal_if_missing and not payload.confirm_virustotal_submission:
        raise HTTPException(status_code=400, detail="Confirm VirusTotal dataset submission explicitly before requesting a fresh scan.")
    if payload.submit_urlscan_private and not payload.confirm_urlscan_submission:
        raise HTTPException(status_code=400, detail="Confirm the fresh private URLScan submission explicitly.")
    if (payload.submit_virustotal_if_missing or payload.submit_urlscan_private) and not payload.include_external_reputation:
        raise HTTPException(status_code=400, detail="Fresh provider submissions require external reputation checks and external-sharing consent.")
    if payload.include_live_inspection and (not payload.confirm_live_crawl or not payload.confirm_network_checks):
        raise HTTPException(status_code=400, detail="Confirm both network checks and bounded live crawling before fetching the target website.")

    started = time.monotonic()
    try:
        base = analyze_url(payload.url)
        normalized_url = base["normalized_url"]
        parsed_host = (urlsplit(normalized_url).hostname or "").strip("[]").rstrip(".").lower()
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    local_score = int(base.get("risk_score") or 0)
    local_signals = list(base.get("signals") or [])
    modules = [_status_module("local_heuristics", "completed", "Explainable URL-text rules ran locally; this module does not fetch the submitted URL.")]
    sensitive_url = intel.has_sensitive_query(normalized_url)
    technical = {
        "dns": {"status": "not_requested", "message": "Consent for DNS/TLS metadata was not given."},
        "tls": {"status": "not_requested", "message": "Consent for DNS/TLS metadata was not given."},
    }
    whois_result = {"status": "not_requested", "target": parsed_host, "summary": "Consent for registration lookup was not given."}
    live_result: dict | None = None
    external_result: dict | None = None
    tasks: dict[str, object] = {}

    if payload.confirm_network_checks:
        if _flag("PHISHSHIELD_NETWORK_METADATA_ENABLED"):
            tasks["technical"] = inspect_network_metadata(normalized_url)
            modules.append(_status_module("dns_tls", "queued", "Collecting DNS record and TLS certificate metadata."))
            if _flag("PHISHSHIELD_WHOIS_ENABLED"):
                _check_service_rate(request, _whois_rate_events, _WHOIS_RATE_LIMIT, _WHOIS_RATE_WINDOW, "WHOIS/RDAP lookup")
                tasks["whois"] = intel.lookup_whois_rdap(normalized_url)
            else:
                whois_result = {"status": "disabled", "target": parsed_host, "summary": "WHOIS/RDAP is disabled by backend configuration."}
        else:
            technical = {
                "dns": {"status": "disabled", "message": "Enable PHISHSHIELD_NETWORK_METADATA_ENABLED after configuring abuse controls."},
                "tls": {"status": "disabled", "message": "Enable PHISHSHIELD_NETWORK_METADATA_ENABLED after configuring abuse controls."},
                "certificate_transparency": {"status": "disabled", "summary": "Enable PHISHSHIELD_NETWORK_METADATA_ENABLED after configuring abuse controls.", "entries": []},
            }
            whois_result = {"status": "disabled", "target": parsed_host, "summary": "Network metadata and WHOIS/RDAP are disabled by backend configuration."}

        if payload.include_live_inspection:
            if not _flag("PHISHSHIELD_INSPECT_ENABLED"):
                live_result = {"status": "disabled", "pages": [], "errors": ["Live inspection is disabled by backend configuration."]}
            elif sensitive_url:
                live_result = {"status": "blocked_sensitive_url", "pages": [], "errors": ["Live fetch skipped because the URL query looks token/session/reset/invite-related. Remove sensitive query parameters and retry with a sanitized URL."]}
            else:
                _check_inspect_rate(request)
                if _inspect_semaphore.locked():
                    live_result = {"status": "busy", "pages": [], "errors": ["The inspector is busy. Retry after the current investigation finishes."]}
                else:
                    async def _run_full_live_inspection():
                        async with _inspect_semaphore:
                            return await asyncio.wait_for(inspect_public_site(normalized_url, payload.max_pages), timeout=65)
                    tasks["live"] = _run_full_live_inspection()
        else:
            live_result = {"status": "not_requested", "pages": [], "errors": []}
    else:
        live_result = {"status": "not_requested", "pages": [], "errors": []}

    if payload.include_external_reputation:
        if not _flag("PHISHSHIELD_REPUTATION_ENABLED"):
            external_result = {
                "status": "disabled", "target": normalized_url, "configured_provider_count": 0,
                "providers": {key: {"status": "disabled", "summary": "External reputation is disabled by backend configuration."} for key in ("virustotal", "google_webrisk", "urlscan", "abuseipdb")},
                "limitations": ["Enable external reputation only after quotas, persistent rate limits, and abuse monitoring are configured."],
            }
        elif sensitive_url:
            external_result = {
                "status": "blocked_sensitive_url", "target": normalized_url, "configured_provider_count": 0,
                "providers": {key: {"status": "blocked_sensitive_url", "summary": "Not queried because the URL appears to contain sensitive query parameters. Remove the sensitive query before sharing with providers."} for key in ("virustotal", "google_webrisk", "urlscan", "abuseipdb")},
                "limitations": ["No reputation provider was queried for this sensitive URL."],
            }
        else:
            _check_service_rate(request, _reputation_rate_events, _REPUTATION_RATE_LIMIT, _REPUTATION_RATE_WINDOW, "Reputation lookup")
            tasks["reputation"] = asyncio.wait_for(
                intel.lookup_reputation(normalized_url, submit_unknown_to_virustotal=payload.submit_virustotal_if_missing, submit_urlscan_private=payload.submit_urlscan_private, include_whois=False),
                timeout=35,
            )
    else:
        external_result = {
            "status": "not_requested", "target": normalized_url, "configured_provider_count": 0,
            "providers": {key: {"status": "not_requested", "summary": "Not queried. Enable external sharing to request this provider."} for key in ("virustotal", "google_webrisk", "urlscan", "abuseipdb")},
            "limitations": ["Third-party reputation providers were not queried."],
        }

    if tasks:
        names = list(tasks)
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, BaseException):
                if name == "technical":
                    technical = {"dns": {"status": "error", "message": f"DNS metadata failed ({type(result).__name__})."}, "tls": {"status": "error", "message": f"TLS metadata failed ({type(result).__name__})."}, "certificate_transparency": {"status": "error", "summary": f"Certificate transparency lookup failed ({type(result).__name__}).", "entries": []}}
                    modules.append(_status_module("dns_tls", "error", "DNS/TLS lookup did not complete."))
                elif name == "whois":
                    whois_result = {"status": "error", "target": parsed_host, "summary": f"WHOIS/RDAP failed ({type(result).__name__})."}
                elif name == "live":
                    live_result = {"status": "error", "pages": [], "errors": [f"Live inspection failed ({type(result).__name__})."]}
                elif name == "reputation":
                    external_result = {"status": "error", "target": normalized_url, "configured_provider_count": 0, "providers": {key: {"status": "error", "summary": "Provider lookup failed or exceeded its time budget."} for key in ("virustotal", "google_webrisk", "urlscan", "abuseipdb")}, "limitations": []}
                continue
            if name == "technical":
                technical = result
                modules.append(_status_module("dns_tls", "completed", f"DNS status: {result.get('dns', {}).get('status', 'unknown')}; TLS status: {result.get('tls', {}).get('status', 'unknown')}."))
                ct_state = (result.get("certificate_transparency") or {}).get("status", "unknown")
                modules.append(_status_module("certificate_transparency", ct_state, (result.get("certificate_transparency") or {}).get("summary", "No CT summary returned.")))
            elif name == "whois":
                whois_result = result
            elif name == "live":
                live_result = score_inspection_result(result)
            elif name == "reputation":
                external_result = result

    provider_results = (external_result or {}).get("providers") or {}
    all_signals = list(local_signals)
    score_candidates = [local_score]
    if isinstance(live_result, dict) and live_result.get("risk_score") is not None:
        score_candidates.append(int(live_result.get("risk_score") or 0))
        all_signals.extend(live_result.get("signals") or [])

    # Provider matches are kept as separately attributed signals. Shared-IP abuse score is
    # deliberately weighted lower than an explicit URL threat-list match.
    provider_floor = 0
    vt = provider_results.get("virustotal") or {}
    if int(vt.get("malicious") or 0) > 0:
        provider_floor = max(provider_floor, 95)
        all_signals.append({"id": "vt-malicious", "title": "VirusTotal malicious engine detections", "detail": f"VirusTotal reported {vt.get('malicious')} malicious detection(s); inspect the full engine result list and analysis timestamp.", "points": 95, "severity": "high"})
    elif int(vt.get("suspicious") or 0) > 0:
        provider_floor = max(provider_floor, 65)
        all_signals.append({"id": "vt-suspicious", "title": "VirusTotal suspicious engine detections", "detail": f"VirusTotal reported {vt.get('suspicious')} suspicious detection(s).", "points": 65, "severity": "high"})
    web_risk = provider_results.get("google_webrisk") or {}
    if web_risk.get("status") == "threat_found":
        provider_floor = max(provider_floor, 98)
        all_signals.append({"id": "webrisk-match", "title": "Google Web Risk threat-list match", "detail": ", ".join(web_risk.get("threat_types") or []) or str(web_risk.get("summary") or "Threat-list match reported."), "points": 98, "severity": "high"})
    urlscan = provider_results.get("urlscan") or {}
    if urlscan.get("status") == "threat_found":
        provider_floor = max(provider_floor, 85)
        all_signals.append({"id": "urlscan-malicious", "title": "Historical URLScan malicious verdict", "detail": "A historical result reports a malicious verdict; verify its age and exact URL.", "points": 85, "severity": "high"})
    abuse = provider_results.get("abuseipdb") or {}
    if int(abuse.get("abuse_confidence_score") or 0) >= 90:
        provider_floor = max(provider_floor, 55)
        all_signals.append({"id": "abuseipdb-high", "title": "High AbuseIPDB score for resolved public IP", "detail": "IP-level reputation may reflect shared hosting or a reassigned address rather than the target domain alone.", "points": 55, "severity": "medium"})
    score_candidates.append(provider_floor)
    unique_signals = []
    seen_ids = set()
    for signal in all_signals:
        sid = str(signal.get("id") or "")
        if sid and sid in seen_ids:
            continue
        if sid:
            seen_ids.add(sid)
        unique_signals.append(signal)
    score = min(100, max(score_candidates))
    verdict = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "INCONCLUSIVE"

    if not any(module.get("name") == "certificate_transparency" for module in modules):
        ct_state = (technical.get("certificate_transparency") or {}).get("status", "unknown")
        ct_summary = (technical.get("certificate_transparency") or {}).get("summary", "No CT summary returned.")
        modules.append(_status_module("certificate_transparency", ct_state, ct_summary))
    if not any(module.get("name") == "dns_tls" for module in modules):
        dns_state = (technical.get("dns") or {}).get("status", "unknown")
        tls_state = (technical.get("tls") or {}).get("status", "unknown")
        modules.append(_status_module("dns_tls", dns_state, f"DNS status: {dns_state}; TLS status: {tls_state}."))
    if external_result:
        external_result["whois"] = whois_result
        for key in ("virustotal", "google_webrisk", "urlscan", "abuseipdb"):
            item = provider_results.get(key) or {}
            modules.append(_status_module(key, item.get("status", "unknown"), item.get("summary", "No result returned.")))
    modules.append(_status_module("whois_rdap", whois_result.get("status", "unknown"), whois_result.get("summary", "No result returned.")))
    if live_result:
        pages = live_result.get("inspection", {}).get("pages", []) if isinstance(live_result.get("inspection"), dict) else live_result.get("pages", [])
        modules.append(_status_module("live_inspection", live_result.get("status", "completed" if pages else "unavailable"), f"Inspected {len(pages)} page(s); discovered {sum(len(p.get('external_links', [])) for p in pages)} external link(s)."))

    base.update({
        "id": uuid.uuid4().hex[:16],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": "FULL URL INVESTIGATION",
        "verdict": verdict,
        "risk_score": score,
        "risk_level": "high" if score >= 60 else "medium" if score >= 30 else "low",
        "signals": unique_signals,
        "signal_count": len([x for x in unique_signals if int(x.get("points") or 0) > 0]),
        "technical": technical,
        "whois_lookup": whois_result,
        "external_reputation": external_result,
        "live_inspection": (live_result.get("inspection") if isinstance(live_result, dict) and live_result.get("inspection") else live_result) if live_result else None,
        "investigation_modules": modules,
        "source_scores": {"local_heuristic": local_score, "live_page": (live_result or {}).get("risk_score") if isinstance(live_result, dict) else None, "provider_evidence_floor": provider_floor},
        "coverage_summary": {
            "max_pages_requested": payload.max_pages if payload.include_live_inspection else 0,
            "pages_inspected": len((live_result or {}).get("inspection", {}).get("pages", [])) if isinstance(live_result, dict) and isinstance(live_result.get("inspection"), dict) else 0,
            "provider_count_configured": (external_result or {}).get("configured_provider_count", 0),
            "network_checks_confirmed": payload.confirm_network_checks,
            "external_reputation_requested": payload.include_external_reputation,
            "virustotal_submission_requested": payload.submit_virustotal_if_missing,
            "urlscan_private_submission_requested": payload.submit_urlscan_private,
            "sensitive_url_blocked_from_external_sharing": sensitive_url,
            "ct_entries_returned": len((technical.get("certificate_transparency") or {}).get("entries") or []),
            "live_external_links_observed": sum(len(page.get("external_links") or []) for page in ((live_result or {}).get("inspection") or {}).get("pages", [])) if isinstance(live_result, dict) else 0,
            "live_external_resources_observed": sum(len(page.get("external_resources") or []) for page in ((live_result or {}).get("inspection") or {}).get("pages", [])) if isinstance(live_result, dict) else 0,
        },
        "recommendation": "Review each source's evidence and freshness. A positive threat-list match warrants caution; a no-match, clean-looking certificate, or low score does not prove safety.",
        "limitations": list(dict.fromkeys(
            list(base.get("limitations", []))
            + ["This is not VirusTotal and cannot guarantee complete coverage or identical results.",
               "The crawler is capped at 10 same-origin public pages; it does not execute JavaScript, log in, submit forms, download files, or crawl third-party domains.",
               "DNS/RDAP/reputation results can be incomplete, stale, unavailable, or rate-limited.",
               "If fresh VirusTotal submission was requested, the URL may be added to VirusTotal's community dataset. Never submit confidential/token-bearing URLs."]
            + (external_result or {}).get("limitations", [])
            + (technical.get("dns", {}).get("limitations", []) if isinstance(technical.get("dns"), dict) else [])
        )),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    })
    store.save(base)
    return base

@app.get("/api/v1/history")
async def api_history():
    return {"items": store.recent(100)}

@app.get("/api/v1/scan/{scan_id}")
async def api_scan_detail(scan_id: str):
    item = store.get_scan(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan not found")
    return item

@app.get("/report/{scan_id}.json")
async def report(scan_id: str):
    item = store.get_scan(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(item, headers={"Content-Disposition": f'attachment; filename="phishshield-{scan_id}.json"'})
