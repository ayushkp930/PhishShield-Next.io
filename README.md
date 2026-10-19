# PhishShield Next 3.0

**A defensive phishing investigation workbench** for suspicious URLs, raw email messages, HTML files, and bounded public-page inspection. It includes a browser-only frontend for GitHub Pages, a FastAPI backend, a CLI, explainable indicators, downloadable JSON/CSV reports, and browser-local case history.

> **Important limitation:** PhishShield is a triage aid, not a definitive verdict, anti-virus engine, or replacement for an organization's mail gateway and threat-intelligence process. `INCONCLUSIVE` does not mean safe. Live inspection is bounded and does not execute JavaScript or submit forms.

## What is included

### Browser UI (works as a static GitHub Pages site)
- Modern responsive cyber-operations dashboard; no third-party JavaScript libraries or analytics.
- URL/domain heuristic triage: URL user-info, HTTP, raw IP hosts, typosquatting-style brand tokens, punycode, suspicious TLD heuristics, long URLs, redirect parameters, suspicious file extensions, URL shorteners, and other explainable signals.
- Email/message paste and `.eml` / `.txt` / `.log` / `.json` upload with a 2 MB client-side file cap. Email content stays in the browser for local analysis.
- Local HTML source analysis: password fields, external form actions, iframes, hidden iframes, outbound links, and title extraction. Uploaded HTML is parsed as text, never rendered.
- Batch scan of up to 200 URLs, with CSV export.
- Investigation reports with scored indicators, recommended next steps, limitations, JSON export, and browser Print / Save as PDF.
- Case history stored in browser `localStorage`; export JSON or clear it at any time.
- Optional API configuration in Settings. The frontend does not contain a third-party API key.

### Backend and CLI
- `POST /api/v1/scan` — local URL heuristics.
- `POST /api/v1/email-analyze` — MIME/header/body triage, attachment filename metadata, reported SPF/DKIM/DMARC status parsing, URL extraction and URL triage. It does not extract or execute attachment content.
- `POST /api/v1/inspect` — optional bounded inspection of up to 5 public HTML pages on the same origin. It records redirect chains, HTTP status, title, selected response headers, form destinations, password fields, iframes and same-origin links. It does not visit external links.
- `GET /health`, `GET /api/v1/history`, `GET /api/v1/scan/{id}`, `GET /report/{id}.json`, interactive docs at `/api/docs`.
- CLI commands: `phishshield scan URL`, `phishshield email FILE`, `phishshield inspect URL --pages 3`, and `phishshield web`.
- SQLite report store for backend-originated scans.

### Safe inspection boundaries
- The live inspector only accepts HTTP/HTTPS on standard ports 80/443 and uses a custom DNS resolver that rejects non-global/private/reserved addresses. Redirect targets are revalidated, each response is capped at 1 MB, redirects are bounded, per-request timeouts are enforced, page budget is at most five, and same-origin links only are followed.
- It does not run JavaScript, authenticate, submit forms, exploit vulnerabilities, download executable files, or follow off-site links.
- Live inspection is **disabled by default in a deployment**. In a local `.env` created from `.env.example`, it is enabled for a local workstation. Treat public URL fetching as an abuse-sensitive feature.
- The in-process rate limiter is an emergency backstop, not a complete anti-abuse system. Do not expose the live inspection endpoint to the public internet without additional durable rate limiting, authentication/challenge or abuse prevention, monitoring, usage limits and a reviewed deployment threat model.

## Run locally (Linux / Kali / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
cp .env.example .env
phishshield web
```

Open `http://127.0.0.1:8000`. The static UI and API are served from the same local origin. The `.env.example` configuration enables bounded live inspection locally. Keep the server bound to `127.0.0.1` unless there is a specific reason to expose it.

### CLI examples

```bash
phishshield scan 'https://secure-login-paypal.account-check.click/verify'
phishshield scan 'https://example.com/login' --json > report.json
phishshield email sample.eml --json > email-report.json
# Explicitly fetch up to 3 pages from a public site (CLI-only; respects same-origin limits)
phishshield inspect 'https://public.example' --pages 3 --json > page-report.json
pytest -q
```

The CLI email analyzer parses message/MIME metadata and reports attachment **names** only; it does not save or execute attachment payloads. The `inspect` command performs a deliberate, bounded network fetch of a public website; use it only on targets you are authorized to investigate.

## Deploy the website to GitHub Pages

The `docs/` folder is a complete static site. No Python backend is needed for URL text triage, email paste/upload, HTML source inspection, local case history, batch analysis or report exports.

1. Push this repository to GitHub.
2. Open **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select your default branch (usually `main`) and folder **`/docs`**, then Save.
5. Wait for the Pages deployment to complete and open the URL shown by GitHub.

The site is useful in static-only mode. The **Page inspection** feature needs a separate API backend; set its HTTPS base URL under **Settings**. The backend must allow the website's exact origin in `PHISHSHIELD_ALLOWED_ORIGINS`. For GitHub Pages project sites, the origin is `https://YOUR-USERNAME.github.io` (do not include the repository path in CORS origin).

## Optional backend deployment

You can deploy the API separately (for example to a Python web service). The API should use HTTPS and a durable database/storage plan if reports need to survive restarts. Set:

- `PHISHSHIELD_ALLOWED_ORIGINS` to a comma-separated list of exact trusted website origins.
- `PHISHSHIELD_INSPECT_ENABLED=false` for a public service unless you have added strong anti-abuse protections. Enable only for a controlled deployment after review.
- `PHISHSHIELD_DB_PATH` to a writable path; persistent storage must be configured in the hosting platform if history should survive redeploys.

Example start command:

```bash
pip install .
uvicorn phishshield.web:app --host 0.0.0.0 --port "$PORT"
```

To run with bounded inspection locally, set `PHISHSHIELD_INSPECT_ENABLED=true` in `.env`. **Never add a VirusTotal, URLScan, or other provider secret to the frontend JavaScript or GitHub Pages repo.** Those providers are not integrated in this release; avoid claiming external reputation checks took place.

## Reports and privacy

- Static UI: analysis is run in the user's browser. Case history and API base URL are stored in browser local storage; use the UI's clear-data controls on shared devices.
- Uploaded files are read as text in-browser and are not sent to the API by the upload flow.
- When the user explicitly chooses **Page inspection**, the URL is sent to the configured backend and the backend fetches a bounded amount of page content. Do not inspect private, confidential, or unauthorized targets.
- Do not paste passwords, session cookies, tokens, private keys, or confidential email content into a shared/public instance.
- PDF export uses the browser's Print / Save as PDF function. JSON reports are produced locally in the browser or by the backend API.

## Testing

```bash
python -m compileall -q phishshield
pytest -q
node --check docs/assets/app.js
```

## Project structure

```text
docs/                   GitHub Pages static app
phishshield/analyzer.py Local URL + email triage for API/CLI
phishshield/live_inspector.py Bounded public page inspector
phishshield/web.py      FastAPI backend
phishshield/cli.py      CLI
phishshield/store.py    SQLite report store
phishshield/static_site/Packaged UI fallback for installed backend
legacy/                 Original PhishShield Pro project, preserved
 tests/                  Regression and safety tests
```

## Not yet included

No commercial threat-intelligence API, cloud browser sandbox, ML model, attachment detonation, SPF/DKIM/DMARC DNS verification, multi-user authentication, signed evidence chain, or enterprise case-management/SIEM workflow is included. Those must be implemented and validated before the project is described as production-grade or enterprise-ready.
