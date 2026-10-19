"""Local-first, non-fetching phishing triage. Does not visit submitted URLs."""
from __future__ import annotations
from urllib.parse import urlsplit, unquote
from datetime import datetime, timezone
import ipaddress, re, hashlib

URL_RE = re.compile(r"^(https?://)?([^/\s?#]+)([^\s]*)?$", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
BRANDS = ("paypal", "microsoft", "office365", "google", "apple", "amazon", "netflix", "facebook", "instagram", "docusign", "dropbox", "outlook", "coinbase")
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "work", "support", "country", "gq", "tk", "ml", "cf"}
REDIRECT_KEYS = {"redirect", "redirect_url", "return", "returnurl", "continue", "next", "url", "dest", "destination", "goto"}

def _domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    if host.count(":") == 1 and host.rsplit(":",1)[1].isdigit():
        host = host.rsplit(":",1)[0]
    return host.encode("idna").decode("ascii") if host else ""

def analyze_url(raw: str) -> dict:
    original = (raw or "").strip()
    if not original or len(original) > 4096:
        raise ValueError("Enter a URL between 1 and 4096 characters.")
    candidate = original if re.match(r"^https?://", original, re.I) else "https://" + original
    try:
        parts = urlsplit(candidate)
        host = _domain(parts.hostname or "")
        port = parts.port
    except (ValueError, UnicodeError):
        raise ValueError("That URL could not be parsed. Check the hostname and port.")
    if parts.scheme.lower() not in {"http", "https"} or not host or any(c.isspace() for c in host):
        raise ValueError("Only valid HTTP or HTTPS URLs/domains are supported.")
    if "." not in host and host != "localhost":
        raise ValueError("Enter a fully qualified domain name or an IP address.")
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        ip, is_ip = None, False
    signals=[]
    def add(key, title, detail, points, severity="medium"):
        signals.append({"id":key,"title":title,"detail":detail,"points":points,"severity":severity})
    if parts.scheme.lower() == "http": add("http", "Unencrypted HTTP", "The URL does not use HTTPS; traffic integrity and confidentiality may be weaker.", 8, "low")
    if parts.username is not None or parts.password is not None: add("userinfo", "Credentials embedded in URL", "User-info before the hostname can disguise the destination in a copied link.", 24, "high")
    if is_ip:
        if not (ip.is_global): add("nonpublic-ip", "Non-public IP address", "The destination resolves syntactically to a non-global IP; this is not a public-site reputation verdict.", 0, "info")
        else: add("ip-host", "IP-address hostname", "Public IP URLs can be legitimate, but are also commonly used in low-cost phishing infrastructure.", 12, "medium")
    labels=host.split(".")
    if len(host) > 70: add("long-host", "Unusually long hostname", "Long hostnames can hide brand-like strings or make destinations hard to inspect.", 8, "low")
    if host.count("-") >= 3: add("hyphens", "Multiple hyphens in hostname", "Several hyphens can be used in lookalike or disposable domains.", 8, "low")
    if sum(ch.isdigit() for ch in host) >= 5 and not is_ip: add("digits", "Many digits in hostname", "A high digit count can be a weak signal of generated or deceptive infrastructure.", 6, "low")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS: add("tld", "Higher-abuse TLD heuristic", f".{tld} has appeared in abuse datasets; TLD alone does not prove maliciousness.", 8, "low")
    if host in SHORTENERS: add("shortener", "URL shortener", "The final destination is obscured until the link is expanded safely.", 12, "medium")
    if len(parts.path) > 100: add("long-path", "Long URL path", "The long path may obscure the meaningful destination or carry tracking payloads.", 5, "low")
    decoded=unquote(parts.path + "?" + parts.query).lower()
    keyword_hits=[w for w in ("login", "verify", "password", "secure", "account", "signin", "auth", "wallet", "invoice", "payment", "reset") if w in decoded]
    if len(keyword_hits) >= 3: add("keywords", "Multiple account-action keywords", "URL path/query contains: " + ", ".join(keyword_hits[:6]) + ". Context matters; keywords alone are not proof.", 10, "medium")
    if any(k in parts.query.lower() for k in REDIRECT_KEYS): add("redirect", "Redirect-style parameter", "A query parameter may forward users elsewhere; inspect the destination before trusting it.", 8, "low")
    if host.startswith("xn--") or ".xn--" in host: add("punycode", "Internationalized hostname", "Punycode hostnames can be legitimate but may also be used for visual impersonation.", 12, "medium")
    brand_hits=[b for b in BRANDS if b in host and not (host == b+".com" or host.endswith("."+b+".com"))]
    if brand_hits: add("brand-lookalike", "Brand keyword in non-canonical hostname", "Brand-like term(s) in hostname: " + ", ".join(brand_hits) + ". This heuristic can produce false positives.", 18, "high")
    if len(labels) >= 5: add("subdomains", "Deeply nested subdomains", f"Hostname contains {len(labels)} labels; read the registered domain from right to left.", 6, "low")
    if not signals: add("no-obvious-patterns", "No obvious URL pattern flags", "This only means local heuristics did not find obvious red flags; it does not establish that the URL is safe.", 0, "info")
    score=min(100,sum(s["points"] for s in signals))
    if score >= 60: verdict,level="HIGH RISK","high"
    elif score >= 30: verdict,level="SUSPICIOUS","medium"
    else: verdict,level="INCONCLUSIVE","low"
    return {"id":hashlib.sha256(original.encode()).hexdigest()[:16],"created_at":datetime.now(timezone.utc).isoformat(),"input":original,"normalized_url":candidate,"hostname":host,"verdict":verdict,"risk_score":score,"risk_level":level,"signals":signals,"signal_count":len([x for x in signals if x["points"]]),"limitations":["This is a heuristic triage result, not a definitive malware verdict.","PhishShield does not open or fetch the submitted URL.","No external reputation provider is queried by the local-only analyzer.","A low score must not be interpreted as proof of safety."],"recommendation":("Do not open the link. Verify the sender through a separate trusted channel and submit the URL to your security team." if score>=60 else "Do not enter credentials or download files. Verify the hostname and sender independently; use approved threat-intelligence tools if needed." if score>=30 else "No strong local heuristic signal was found. Treat the link as unverified and check reputation using your organization's approved tools.")}

def analyze_email_text(text: str) -> dict:
    """Perform local email/message triage without executing content or opening URLs."""
    from email import policy
    from email.parser import Parser
    from email.utils import getaddresses
    from html.parser import HTMLParser
    from urllib.parse import urlsplit

    if not text or not text.strip():
        raise ValueError("Email text is empty.")
    if len(text) > 1_000_000:
        raise ValueError("Email text exceeds the 1 MB analysis limit.")

    msg = Parser(policy=policy.default).parsestr(text, headersonly=False)
    header_names = (
        "From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID",
        "Authentication-Results", "Received-SPF", "Content-Type"
    )
    headers = {name.lower().replace("-", "_"): str(msg.get(name, ""))[:2000] for name in header_names if msg.get(name) is not None}
    from_values = [a.lower() for _, a in getaddresses(msg.get_all("From", [])) if a]
    reply_values = [a.lower() for _, a in getaddresses(msg.get_all("Reply-To", [])) if a]
    return_values = [a.lower() for _, a in getaddresses(msg.get_all("Return-Path", [])) if a]

    def domain(addr: str) -> str:
        return addr.rsplit("@", 1)[1].strip().lower().rstrip(".") if "@" in addr else ""

    # Parse MIME metadata only. Attachment bodies are never extracted to disk or executed.
    attachment_names = []
    html_chunks = []
    body_chunks = []
    try:
        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            filename = part.get_filename()
            if filename:
                attachment_names.append(str(filename)[:255])
            content_type = part.get_content_type().lower()
            if content_type in {"text/plain", "text/html"}:
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        if content_type == "text/html":
                            html_chunks.append(content[:500_000])
                        else:
                            body_chunks.append(content[:500_000])
                except (LookupError, UnicodeError, KeyError, TypeError):
                    continue
    except Exception:
        # Malformed MIME must not crash the analyzer; raw text is still triaged below.
        pass

    content_text = "\n".join(body_chunks + html_chunks)
    working_text = (text + "\n" + content_text)[:1_000_000]
    urls = sorted(set(re.findall(r"(?i)\bhttps?://[^\s<>\"']+", working_text)))[:100]
    urls = [u.rstrip("),.;!?]}>") for u in urls]
    urls = sorted(set(u for u in urls if u))
    risky_ext = re.compile(r"\.(?:exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|wsh|hta|msi|msp|ps1|psm1|jar|iso|img|lnk|reg|dll|docm|xlsm|pptm|one|application)$", re.I)
    risky_attachments = sorted(set(name for name in attachment_names if risky_ext.search(name)))
    signals = []
    def add(key, title, detail, points, severity="medium"):
        signals.append({"id": key, "title": title, "detail": detail, "points": points, "severity": severity})

    if from_values and reply_values and domain(from_values[0]) and domain(reply_values[0]) and domain(from_values[0]) != domain(reply_values[0]):
        add("reply-mismatch", "Reply-To domain differs from From", f"From domain: {domain(from_values[0])}; Reply-To domain: {domain(reply_values[0])}. This can be legitimate, but verify the sender out-of-band.", 18, "high")
    if from_values and return_values and domain(from_values[0]) and domain(return_values[0]) and domain(from_values[0]) != domain(return_values[0]):
        add("return-path-mismatch", "Return-Path differs from From", "The envelope return path differs from the visible sender domain. Mailing platforms can cause legitimate differences.", 7, "medium")

    auth_values = " ".join(str(x) for x in (msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", [])))
    for method in ("spf", "dkim", "dmarc"):
        states = re.findall(rf"\b{method}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_values, re.I)
        states = list(dict.fromkeys(x.lower() for x in states))
        failed = [x for x in states if x in {"fail", "softfail", "none", "temperror", "permerror", "neutral"}]
        if failed:
            add(f"auth-{method}", f"{method.upper()} authentication needs review", f"Supplied headers report {method.upper()}={', '.join(failed)}. Raw header text can be forged; validate in a trusted mail system.", 14 if method == "dmarc" else 10, "high")
        elif "pass" in states:
            add(f"auth-{method}-pass", f"{method.upper()} pass reported", f"Supplied headers report {method.upper()} pass. This is not independently verified and does not prove a message is safe.", 0, "info")

    urgency = re.findall(r"(?i)\b(?:urgent|immediately|within\s+\d+\s+hours?|account\s+suspended|verify\s+(?:your\s+)?account|password\s+expires|final\s+warning|action\s+required|payment\s+failed)\b", working_text)
    if urgency:
        add("urgency", "Urgency or account-pressure language", f"Detected {len(urgency)} urgency phrase match(es). Review in context; wording alone is not proof of phishing.", min(12, len(urgency) * 4), "medium")
    if re.search(r"(?i)\b(?:password|passcode|one[- ]time code|security code|recovery phrase|seed phrase)\b", working_text) and re.search(r"(?i)\b(?:reply|send|confirm|share|enter|provide|verify)\b", working_text):
        add("credential-request", "Possible credential or secret request", "Message text pairs a sensitive secret with an action request. Never share passwords, OTPs, recovery phrases or session tokens over email.", 18, "high")
    if risky_attachments:
        add("risky-attachment", "Potentially executable or macro-enabled attachment name", "Filename(s): " + ", ".join(risky_attachments[:8]) + ". Filename triage is not malware scanning.", 22, "high")
    if len(urls) >= 5:
        add("many-links", "Multiple links in message", f"Found {len(urls)} distinct URL(s). Review destination domains and context.", 5, "low")
    if re.search(r"(?i)\b(?:wire transfer|gift card|change of bank details|invoice attached|payment overdue)\b", working_text):
        add("payment-pressure", "Financial or payment action language", "Message contains payment-related wording. Verify financial requests through a known-good channel.", 8, "medium")

    html_evidence = {"html_parts": len(html_chunks), "password_fields": 0, "iframes": 0, "hidden_iframes": 0, "external_form_actions": []}
    if html_chunks:
        class SimpleHtmlSignals(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.password_fields = 0
                self.iframes = 0
                self.hidden_iframes = 0
                self.form_actions = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag.lower() == "input" and (attrs.get("type") or "").lower() == "password":
                    self.password_fields += 1
                if tag.lower() == "iframe":
                    self.iframes += 1
                    style = (attrs.get("style") or "").lower().replace(" ", "")
                    if "display:none" in style or "visibility:hidden" in style or "hidden" in attrs or attrs.get("aria-hidden") == "true":
                        self.hidden_iframes += 1
                if tag.lower() == "form":
                    self.form_actions.append(attrs.get("action") or "(current page)")
        parser = SimpleHtmlSignals()
        try:
            for chunk in html_chunks:
                parser.feed(chunk)
        except Exception:
            pass
        html_evidence.update({"password_fields": parser.password_fields, "iframes": parser.iframes, "hidden_iframes": parser.hidden_iframes, "form_actions": parser.form_actions[:50]})
        if parser.password_fields:
            add("html-password-form", "HTML includes a password field", f"Found {parser.password_fields} password-type field(s) in provided HTML. Verify where credentials would be submitted.", 16, "high")
        if parser.hidden_iframes:
            add("html-hidden-iframe", "HTML includes hidden iframe(s)", f"Found {parser.hidden_iframes} hidden iframe(s). Review context and destinations.", 12, "high")
        elif parser.iframes:
            add("html-iframe", "HTML includes iframe(s)", f"Found {parser.iframes} iframe(s). These can be legitimate but may warrant review.", 5, "low")

    if not signals:
        add("no-obvious-patterns", "No obvious message patterns flagged", "Local rules found no strong known pattern in the supplied content. Sender identity and delivery authenticity are still unverified.", 0, "info")
    score = min(100, sum(x["points"] for x in signals))
    verdict = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "INCONCLUSIVE"
    url_reports = []
    for item in urls[:50]:
        try:
            u = analyze_url(item)
            url_reports.append({"input": item, "hostname": u["hostname"], "verdict": u["verdict"], "risk_score": u["risk_score"], "signals": u["signals"]})
        except ValueError:
            url_reports.append({"input": item, "hostname": "", "verdict": "UNPARSEABLE", "risk_score": None, "signals": []})
    flags = [s["detail"] for s in signals if s["points"] > 0]
    return {
        "id": hashlib.sha256((text[:1000] + str(len(text))).encode()).hexdigest()[:16],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "type": "EMAIL",
        "input": str(msg.get("Subject", "Email / message analysis"))[:240],
        "email_chars": len(text),
        "headers": headers,
        "from_headers": [str(x) for x in msg.get_all("From", [])][:3],
        "reply_to_headers": [str(x) for x in msg.get_all("Reply-To", [])][:3],
        "from": from_values[:10],
        "reply_to": reply_values[:10],
        "return_path": return_values[:10],
        "urls": urls,
        "url_reports": url_reports,
        "attachment_names": sorted(set(attachment_names))[:100],
        "risky_attachment_names": risky_attachments,
        "html_evidence": html_evidence,
        "flags": flags,
        "signals": signals,
        "signal_count": len([s for s in signals if s["points"] > 0]),
        "risk_score": score,
        "risk_level": "high" if score >= 60 else "medium" if score >= 30 else "low",
        "verdict": verdict,
        "recommendation": "Treat this message as high risk until independently verified. Do not click links or open attachments; report it to the mail-security team." if score >= 60 else "Treat this message as suspicious. Verify the sender through a known-good channel before interacting." if score >= 30 else "No strong local message heuristic was found. Sender identity and attachment safety remain unverified.",
        "note": "Header/body heuristics only. Authentication results are parsed from supplied header text, not independently validated.",
        "limitations": [
            "Raw header values can be forged unless verified by trusted mail infrastructure.",
            "SPF/DKIM/DMARC reported in the supplied text are not independently checked.",
            "Attachments are not extracted to disk, executed, or scanned by an antivirus engine.",
            "URLs are analyzed as text; no link is fetched by this email analyzer.",
            "A low score or INCONCLUSIVE verdict is not proof of safety.",
        ],
    }
