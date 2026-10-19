# Security policy and safe use

PhishShield Next is a defensive triage project. Use it only on data and systems you are authorized to investigate.

## Important security boundaries

- Browser-only mode treats URLs as text and does not open them.
- Uploaded message / HTML / JSON files are parsed as text. The app does not execute uploaded content or detonate attachments.
- The optional live inspector is disabled by default in deployments. When explicitly enabled, it permits only standard HTTP/HTTPS ports, rejects private/local/reserved IP destinations through a custom DNS resolver, revalidates redirects, caps pages and response bytes, and only follows same-origin page links (maximum 10 HTML pages).
- The live inspector is not a full browser sandbox and should not be exposed publicly without reviewed anti-abuse controls, authentication/challenge, durable rate limits, request monitoring and hosting-level protections.
- Never submit confidential messages, passwords, session cookies, API keys, private keys, or data you do not have permission to inspect.

## Reporting a security issue

Do not publish working exploit details or sensitive target information in public issue threads. Open a private security advisory in the repository host, or contact the maintainer through a verified contact channel listed in that repository. Include a minimal reproducible description and affected version. Avoid uploading real phishing emails that contain personal data or active access tokens.

## Scope

This policy covers the PhishShield Next application code. It does not guarantee that URLs identified by the heuristics are malicious or benign. Risk scoring is not calibrated as a production detection model and must not be used as the only control in an operational security workflow.


## Provider API secrets and indicator privacy

- Store `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`, and `ABUSEIPDB_API_KEY` only in backend environment secrets or a local ignored `.env` file. Never expose keys in `docs/`, browser JavaScript, static hosting settings, screenshots, or committed files.
- If a key is pasted into a chat, issue, terminal recording, or repository, treat it as compromised and rotate/revoke it before use.
- The reputation endpoint is disabled by default on the Render blueprint. Do not enable it on an unrestricted public service without authentication/challenge, durable per-user/IP and global quota controls, monitoring, and a way to shut the feature off quickly. The in-memory rate limiter is not sufficient by itself for a public production service.
- External lookup can disclose indicators to third parties. Never query private reset/invite/session/token URLs or confidential indicators. VirusTotal may add queried indicators to its threat-intelligence dataset. A fresh URLScan request launches a remote browser; private visibility limits listing visibility but does not imply the provider does not process the URL.
