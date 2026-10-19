# PhishShield Next 3.2.0 — API setup

## Provider mapping

| Environment variable | Provider | What PhishShield uses it for |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Read cached URL reports including reported per-engine detections; if separately authorized, submit an unknown URL for fresh analysis. Fresh submissions may become part of VirusTotal's community dataset. |
| `GOOGLE_WEB_RISK_API_KEY` | Google Web Risk | Check the URL against selected social-engineering, malware, and unwanted-software lists. |
| `URLSCAN_API_KEY` | URLScan.io | Search historical scan records by hostname; if separately authorized, launch a fresh private scan in URLScan's remote browser. Private visibility is not a promise of no provider processing. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Check one public IP address resolved from the target hostname. Private/reserved IPs are never sent. |
| *(none)* | WHOIS / RDAP | Look up public domain registration or public-IP network metadata via RDAP. This does not require a provider API key. |
| *(none)* | Cloudflare DNS-over-HTTPS | Retrieve bounded A/AAAA/CNAME/MX/NS/TXT/CAA/SOA and DMARC DNS records. The resolver receives the hostname. |
| *(none)* | crt.sh / public CT logs | Retrieve a bounded sample of already-published certificate-transparency entries (up to 50 displayed). This is not a maliciousness verdict. |
| *(none)* | Public TLS endpoint | Verify certificate trust and collect certificate subject/issuer/SANs/validity/fingerprint, TLS version and cipher for HTTPS on port 443. |
| *(none)* | Bounded same-origin crawler | Fetch up to 10 public HTML pages only after explicit consent; records redirects/forms/headers/links. It does not execute JS or submit forms. |

## Security first

**Any API key pasted into a chat, issue, screenshot, terminal recording, or repository should be considered exposed. Revoke/rotate the four keys shared earlier before using this integration.** Don't reuse the exposed values.

Never place provider secrets in `docs/assets/app.js`, `docs/index.html`, GitHub Pages repository files, or the browser Settings UI. Secrets belong only in backend environment variables. `.env` is ignored by Git; `.env.example` contains blank placeholders only.

## Local Kali setup

```bash
cd ~/projects/PhishShield-Next.io
cp .env.example .env   # skip this if .env already exists; don't overwrite existing settings
nano .env
```

Enter newly rotated keys in `.env`:

```dotenv
VIRUSTOTAL_API_KEY=PASTE_NEW_VIRUSTOTAL_KEY_HERE
GOOGLE_WEB_RISK_API_KEY=PASTE_NEW_WEBRISK_KEY_HERE
URLSCAN_API_KEY=PASTE_NEW_URLSCAN_KEY_HERE
ABUSEIPDB_API_KEY=PASTE_NEW_ABUSEIPDB_KEY_HERE
PHISHSHIELD_NETWORK_METADATA_ENABLED=true
PHISHSHIELD_INSPECT_ENABLED=true
PHISHSHIELD_REPUTATION_ENABLED=true
PHISHSHIELD_WHOIS_ENABLED=true
```

Install/run locally:

```bash
source .venv/bin/activate  # if using your existing virtual environment
pip install -e .
phishshield web
```

The Web UI runs the local heuristic scan without any provider keys. The **Run full investigation** action requires a connected API base URL. DNS/TLS/CT/RDAP checks require `PHISHSHIELD_NETWORK_METADATA_ENABLED=true`; WHOIS/RDAP also requires `PHISHSHIELD_WHOIS_ENABLED=true`. External provider checks require the explicit data-sharing checkbox and `PHISHSHIELD_REPUTATION_ENABLED=true`. Live inspection additionally requires `PHISHSHIELD_INSPECT_ENABLED=true` and its separate checkbox.

## Public backend deployment

The GitHub Pages site is static; it cannot store secrets or execute Python. Deploy the Python service (the repository includes `render.yaml`, `Dockerfile`, and `compose.yaml`) and then:

1. In the backend host's secret/environment settings, add the four provider variables above using newly rotated keys.
2. Set `PHISHSHIELD_ALLOWED_ORIGINS=https://ayushkp930.github.io` for this GitHub Pages project site. CORS origins do **not** include `/PhishShield-Next.io`.
3. Deploy, then test `https://YOUR-BACKEND.example/health`. The response shows only booleans for `providers_configured` and `features`; it never returns key values.
4. In the public GitHub Pages site, open **Settings**, enter the backend origin (e.g. `https://YOUR-BACKEND.example`, without `/api` or a path), test connection, and save.

In `render.yaml`, external reputation, DNS/TLS/CT, page crawling, and WHOIS are intentionally **disabled by default**. The external reputation endpoint uses a per-process rate-limit backstop, but this is not distributed authentication or a complete abuse-control system. Enabling shared provider keys on an unrestricted public backend may allow strangers to consume your quota. Before publicly enabling reputation checks, add robust edge-level rate limits, global usage budgets, abuse monitoring, and an authentication/challenge layer appropriate to your service. Otherwise, keep the endpoint disabled and let users run their own backend.

For a **personal test deployment** after rotating the keys, the corresponding Render Environment flags are `PHISHSHIELD_NETWORK_METADATA_ENABLED=true`, `PHISHSHIELD_INSPECT_ENABLED=true`, `PHISHSHIELD_REPUTATION_ENABLED=true`, and `PHISHSHIELD_WHOIS_ENABLED=true`. Redeploy after changing them. Do not flip all four to `true` on an unrestricted public API until external quotas and abuse prevention are in place. GitHub Pages users will need the backend base URL configured in Settings; the static site cannot call providers directly or hide API secrets.

## Smoke-test endpoints

Only run external reputation lookups with non-sensitive, public indicators that you are authorized to share.

```bash
curl -s https://YOUR-BACKEND.example/health

curl -s -X POST https://YOUR-BACKEND.example/api/v1/whois \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'

curl -s -X POST https://YOUR-BACKEND.example/api/v1/reputation \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com/","confirm_external_sharing":true}'
```

The WHOIS endpoint returns registration metadata. The reputation endpoint calls configured providers in parallel and returns separate evidence blocks; it does not convert all vendor results into one supposedly definitive score. Provider timeouts, quotas, unsupported plans, and absent records are returned as provider statuses.

## CLI commands

```bash
phishshield reputation 'https://example.com/' --json > reputation.json
phishshield whois example.com --json > whois.json
```

For a one-report workflow with a configured backend, use the web dashboard's **Run full investigation** panel. It combines available modules in one report. Tick separate consent only for modules you want to run. The API returns `disabled`, `not_configured`, `rate_limited`, `not_requested` and other statuses rather than treating unavailable sources as clean.

The `reputation` CLI command is an explicit user-initiated operation that sends the indicator to configured providers. It also blocks common secret-bearing query keys (`token`, `code`, `session`, `reset`, `invite`, etc.). Review every indicator before sending it to a third party.

## Official documentation

- [VirusTotal API](https://docs.virustotal.com/)
- [Google Web Risk Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api)
- [URLScan.io API](https://urlscan.io/docs/api/)
- [AbuseIPDB API v2](https://docs.abuseipdb.com/)
- [RDAP overview](https://www.icann.org/rdap)
