from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import store
from .analyzer import analyze_email_text, analyze_url
from .live_inspector import UnsafeTarget, inspect_public_site, score_inspection_result

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
if not (DOCS / "index.html").is_file():
    DOCS = Path(__file__).resolve().parent / "static_site"
app = FastAPI(
    title="PhishShield Next API",
    description="Defensive phishing triage. Heuristic analysis is not a safety verdict.",
    version="3.0.0",
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
    max_pages: int = Field(default=3, ge=1, le=5)

# Per-process emergency backstop. Public deployments must ALSO use a gateway/WAF,
# authentication or challenge, and persistent rate limiting; this is not distributed.
_RATE_WINDOW = int(os.getenv("PHISHSHIELD_INSPECT_WINDOW_SECONDS", "600"))
_RATE_LIMIT = int(os.getenv("PHISHSHIELD_INSPECT_LIMIT", "8"))
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_inspect_semaphore = asyncio.Semaphore(2)

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
    return {"status": "ok", "version": "3.0.0", "mode": "local heuristics plus optional bounded public-page inspection", "api_docs": "/api/docs"}

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

@app.post("/api/v1/inspect")
async def api_inspect(payload: InspectRequest, request: Request):
    if os.getenv("PHISHSHIELD_INSPECT_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=503, detail="Live inspection is disabled on this deployment. Enable it only after adding public-service abuse controls.")
    _check_inspect_rate(request)
    if _inspect_semaphore.locked():
        raise HTTPException(status_code=503, detail="Inspector is busy. Please retry shortly.")
    async with _inspect_semaphore:
        try:
            result = await asyncio.wait_for(inspect_public_site(payload.url, payload.max_pages), timeout=50)
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
