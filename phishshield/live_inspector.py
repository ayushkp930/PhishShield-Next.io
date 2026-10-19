"""Bounded defensive web-page inspection with public-IP-only DNS resolution.

This module intentionally does not execute JavaScript, submit forms, authenticate,
follow off-site links, or download files. It fetches HTML pages only, with strict limits.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import uuid
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from yarl import URL

MAX_URL_LENGTH = 4096
MAX_REDIRECTS = 4
MAX_PAGES = 5
MAX_BODY_BYTES = 1_000_000
REQUEST_TIMEOUT_SECONDS = 7
ALLOWED_PORTS = {80, 443}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")


class UnsafeTarget(ValueError):
    """Raised when a target is outside the inspector's permitted scope."""


class PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self._in_title = False
        self.links: list[str] = []
        self.form_actions: list[str] = []
        self.password_fields = 0
        self.iframes = 0
        self.hidden_iframes = 0
        self.frame_sources: list[str] = []
        self._form_action: str | None = None
        self._form_input_types: list[str] = []
        self.forms_with_password = 0
        self.external_form_actions: list[str] = []

    def handle_starttag(self, tag: str, attrs_tuple):
        attrs = dict(attrs_tuple)
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "a" and attrs.get("href"):
            self._append_url(self.links, attrs["href"])
        elif tag == "form":
            self._form_action = attrs.get("action") or self.base_url
            self._form_input_types = []
        elif tag == "input" and (attrs.get("type") or "").lower() == "password":
            self.password_fields += 1
            self._form_input_types.append("password")
        elif tag == "iframe":
            self.iframes += 1
            if attrs.get("src"):
                self._append_url(self.frame_sources, attrs["src"])
            style = (attrs.get("style") or "").lower()
            if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", "") or attrs.get("aria-hidden", "").lower() == "true" or "hidden" in attrs:
                self.hidden_iframes += 1
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            content = attrs.get("content", "")
            match = re.search(r"url\s*=\s*['\"]?([^'\"]+)" , content, re.I)
            if match:
                self._append_url(self.links, match.group(1))
        elif tag == "base" and attrs.get("href"):
            # Do not change the parsing base after page fetch; resolve base href safely here.
            self._append_url(self.links, attrs["href"])

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            action = self._absolute(self._form_action or self.base_url)
            if action:
                self.form_actions.append(action)
                base_host = (urlsplit(self.base_url).hostname or "").lower()
                action_host = (urlsplit(action).hostname or "").lower()
                if action_host and action_host != base_host:
                    self.external_form_actions.append(action)
            if "password" in self._form_input_types:
                self.forms_with_password += 1
            self._form_action = None
            self._form_input_types = []

    def handle_data(self, data: str):
        if self._in_title:
            self.title += data

    def _absolute(self, value: str) -> str | None:
        try:
            return urljoin(self.base_url, value.strip())
        except Exception:
            return None

    def _append_url(self, target: list[str], value: str):
        abs_url = self._absolute(value)
        if abs_url and abs_url not in target and len(target) < 200:
            target.append(abs_url)


class PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    """Resolve a hostname and refuse the entire answer if any address isn't global."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise OSError(f"DNS resolution failed for {host}") from exc
        addresses = []
        for af, socktype, proto, canonname, sockaddr in infos:
            address = sockaddr[0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise OSError("DNS returned an invalid address") from exc
            if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                raise OSError(f"Blocked non-public destination for {host}")
            addresses.append({
                "hostname": host,
                "host": address,
                "port": port,
                "family": af,
                "proto": proto,
                "flags": socket.AI_NUMERICHOST,
            })
        if not addresses:
            raise OSError(f"No public addresses found for {host}")
        return addresses

    async def close(self):
        return None


def validate_target(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_URL_LENGTH:
        raise UnsafeTarget("Enter a URL between 1 and 4096 characters.")
    candidate = value.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I) and not re.match(r"^https?://", candidate, re.I):
        raise UnsafeTarget("Only HTTP and HTTPS public web URLs are supported.")
    if not re.match(r"^https?://", candidate, re.I):
        candidate = "https://" + candidate
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname or ""
        port = parts.port if parts.port is not None else (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise UnsafeTarget("Invalid URL syntax.") from exc
    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        raise UnsafeTarget("Only HTTP and HTTPS public web URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTarget("URLs containing embedded credentials are not fetched.")
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget("Only standard HTTP/HTTPS ports 80 and 443 are allowed.")
    host = hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
        raise UnsafeTarget("Local, private and reserved hostnames are not allowed.")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip and (not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
        raise UnsafeTarget("Local, private and reserved IP addresses are not allowed.")
    # Strip fragments: they are client-side only and don't belong in the HTTP request.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def _is_html(content_type: str, body: bytes) -> bool:
    return "text/html" in content_type.lower() or b"<html" in body[:5000].lower() or b"<!doctype html" in body[:5000].lower()


def _same_host(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.hostname or "").lower() == (pb.hostname or "").lower() and pa.scheme.lower() == pb.scheme.lower() and (pa.port if pa.port is not None else (443 if pa.scheme == "https" else 80)) == (pb.port if pb.port is not None else (443 if pb.scheme == "https" else 80))


def _looks_like_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return not path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".pdf", ".zip", ".gz", ".exe", ".dmg", ".msi", ".apk", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".docx", ".xlsx", ".pptx"))


async def inspect_public_site(raw_url: str, max_pages: int = 3) -> dict:
    """Inspect one public URL and optionally same-origin HTML pages (max 5 total)."""
    if max_pages < 1 or max_pages > MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}.")
    first_url = validate_target(raw_url)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS, connect=4, sock_read=4)
    connector = aiohttp.TCPConnector(resolver=PublicOnlyResolver(), use_dns_cache=False, limit=4, ssl=True)
    pages: list[dict] = []
    errors: list[str] = []
    redirects: list[str] = []
    queue = [first_url]
    seen: set[str] = set()
    tls_validated = False
    root_host = urlsplit(first_url).hostname or ""
    user_agent = "PhishShield-Next-DefensiveInspector/3.0 (+bounded HTML security review; no JavaScript execution)"
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
        auto_decompress=True,
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
    ) as session:
        while queue and len(pages) < max_pages:
            requested = queue.pop(0)
            try:
                current = validate_target(requested)
            except UnsafeTarget as exc:
                errors.append(f"Blocked URL: {str(exc)}")
                continue
            if current in seen:
                continue
            seen.add(current)
            url_chain = [current]
            final_response = None
            response_bytes = b""
            content_type = ""
            headers: dict[str, str] = {}
            status = 0
            try:
                for hop in range(MAX_REDIRECTS + 1):
                    # PublicOnlyResolver pins socket resolution to the validated global IP result.
                    async with session.get(URL(current), allow_redirects=False, max_redirects=0) as response:
                        status = response.status
                        headers = {k: v[:500] for k, v in response.headers.items() if k.lower() in {
                            "content-type", "server", "location", "strict-transport-security",
                            "content-security-policy", "x-frame-options", "x-content-type-options",
                            "referrer-policy", "permissions-policy", "cache-control", "content-length"
                        }}
                        content_type = response.headers.get("Content-Type", "")
                        if status in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                            if hop >= MAX_REDIRECTS:
                                errors.append(f"Maximum redirect count reached for {current}")
                                final_response = response
                                break
                            location = urljoin(current, response.headers["Location"])
                            try:
                                location = validate_target(location)
                            except UnsafeTarget as exc:
                                errors.append(f"Redirect blocked from {current}: {exc}")
                                final_response = response
                                break
                            redirects.append(location)
                            url_chain.append(location)
                            current = location
                            continue
                        size_hint = response.headers.get("Content-Length")
                        if size_hint and size_hint.isdigit() and int(size_hint) > MAX_BODY_BYTES:
                            errors.append(f"Body exceeds {MAX_BODY_BYTES} byte inspection cap: {current}")
                            final_response = response
                            break
                        chunks = []
                        total = 0
                        async for chunk in response.content.iter_chunked(16384):
                            total += len(chunk)
                            if total > MAX_BODY_BYTES:
                                chunks.append(chunk[: max(0, MAX_BODY_BYTES - (total - len(chunk)))])
                                errors.append(f"Body truncated at {MAX_BODY_BYTES} bytes: {current}")
                                break
                            chunks.append(chunk)
                        response_bytes = b"".join(chunks)
                        final_response = response
                        break
                if final_response is None:
                    errors.append(f"Could not retrieve {current}")
                    continue
                if urlsplit(current).scheme == "https" and status not in {0}:
                    tls_validated = True
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
                if "certificate" in str(exc).lower() or "ssl" in str(exc).lower():
                    tls_validated = False
                errors.append(f"Fetch failed for {current}: {type(exc).__name__}")
                pages.append({"requested_url": requested, "url": current, "status": None, "title": "", "content_type": "", "headers": {}, "redirect_chain": url_chain, "links": [], "external_links": [], "frame_sources": [], "form_actions": [], "external_form_action_urls": [], "password_fields": 0, "iframes": 0, "hidden_iframes": 0, "findings": ["Page fetch failed; this is not evidence that the site is safe."], "error": type(exc).__name__})
                continue

            findings: list[str] = []
            if status >= 400:
                findings.append(f"HTTP response status is {status}; check whether the page is expected to exist.")
            if urlsplit(current).scheme == "http":
                findings.append("Page uses HTTP without transport encryption.")
            if status in {301, 302, 303, 307, 308}:
                findings.append("Redirect limit or blocked redirect stopped page retrieval.")
            title = ""
            internal_links: list[str] = []
            external_links: list[str] = []
            frame_sources: list[str] = []
            form_actions: list[str] = []
            password_fields = iframes = hidden_iframes = external_form_actions = 0
            if _is_html(content_type, response_bytes):
                charset_match = re.search(r"charset=([\w.-]+)", content_type, re.I)
                charset = charset_match.group(1) if charset_match else "utf-8"
                try:
                    body_text = response_bytes.decode(charset, errors="replace")
                except LookupError:
                    body_text = response_bytes.decode("utf-8", errors="replace")
                parser = PageParser(current)
                try:
                    parser.feed(body_text)
                except Exception:
                    findings.append("HTML parser encountered malformed content; inspection may be incomplete.")
                title = " ".join(parser.title.split())[:240]
                password_fields = parser.password_fields
                iframes = parser.iframes
                hidden_iframes = parser.hidden_iframes
                if password_fields:
                    findings.append(f"HTML contains {password_fields} password input field(s); verify form ownership and destination.")
                if parser.external_form_actions:
                    external_form_actions = len(parser.external_form_actions)
                    findings.append(f"{external_form_actions} form action(s) point to a different hostname than the inspected page.")
                if parser.hidden_iframes:
                    hidden_iframes = parser.hidden_iframes
                    findings.append(f"HTML contains {hidden_iframes} hidden iframe(s); inspect the frame destinations and context.")
                elif parser.iframes:
                    findings.append(f"HTML contains {parser.iframes} iframe(s); inspect their purpose and origin.")
                if "strict-transport-security" not in {k.lower() for k in headers} and urlsplit(current).scheme == "https":
                    findings.append("Strict-Transport-Security header not observed on this response.")
                lowered = {k.lower() for k in headers}
                missing = [h for h, label in [("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("x-frame-options", "X-Frame-Options")] if h not in lowered]
                if missing:
                    findings.append("Some common browser security headers were not observed: " + ", ".join(missing) + ".")
                for link in parser.links:
                    try:
                        target = validate_target(link)
                    except UnsafeTarget:
                        continue
                    if _same_host(current, target) and _looks_like_page(target):
                        if target not in internal_links and len(internal_links) < 80:
                            internal_links.append(target)
                    elif (urlsplit(target).hostname or "").lower() != (urlsplit(current).hostname or "").lower():
                        if target not in external_links and len(external_links) < 80:
                            external_links.append(target)
                form_actions = parser.form_actions[:50]
                frame_sources = parser.frame_sources[:50]
                if "content-security-policy" not in lowered:
                    # Informational finding; it contributes no authoritative phishing verdict.
                    pass
            else:
                findings.append("Response was not parsed as HTML; page structure and forms were not inspected.")
            pages.append({
                "requested_url": requested,
                "url": current,
                "status": status,
                "title": title,
                "content_type": content_type[:200],
                "headers": headers,
                "redirect_chain": url_chain,
                "links": internal_links[:50],
                "external_links": external_links[:50],
                "frame_sources": frame_sources,
                "form_actions": form_actions,
                "external_form_actions": external_form_actions,
                "external_form_action_urls": parser.external_form_actions[:50] if _is_html(content_type, response_bytes) else [],
                "password_fields": password_fields,
                "iframes": iframes,
                "hidden_iframes": hidden_iframes,
                "findings": findings,
            })
            if len(pages) < max_pages:
                for link in internal_links:
                    if link not in seen and link not in queue:
                        queue.append(link)
                    if len(queue) >= 20:
                        break
    if not pages:
        raise UnsafeTarget("No pages could be inspected. Review target restrictions and DNS/fetch errors.")
    return {
        "id": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "type": "LIVE INSPECTION",
        "input": raw_url,
        "normalized_url": first_url,
        "hostname": root_host,
        "verdict": "INCONCLUSIVE",
        "risk_score": 0,
        "signals": [],
        "recommendation": "Review each finding and verify the site using approved threat-intelligence sources. Missing security headers or a password form are context signals, not proof of phishing.",
        "limitations": [
            "Only public HTTP/HTTPS web pages are fetched; local/private/reserved IP addresses are blocked by a public-only DNS resolver.",
            "The inspector does not execute JavaScript, authenticate, submit forms, upload files, or download executable content.",
            "Internal links are followed only within the same origin and up to the selected page budget; external links are listed but not visited.",
            "This is a bounded page inspection, not a full browser sandbox, malware scan, or definitive phishing verdict.",
            "Do not expose a public scanning API without robust authentication/rate limiting, monitoring and abuse controls.",
        ],
        "inspection": {"pages": pages, "redirect_chain": redirects, "errors": errors, "tls_validated": tls_validated, "max_pages": max_pages, "limits": {"max_body_bytes_per_page": MAX_BODY_BYTES, "max_redirects": MAX_REDIRECTS, "timeout_seconds": REQUEST_TIMEOUT_SECONDS}},
    }

def score_inspection_result(result: dict) -> dict:
    """Attach transparent heuristic scoring to a bounded page inspection."""
    result = dict(result)
    inspection = result.get("inspection", {})
    pages = inspection.get("pages", [])
    findings: dict[str, dict] = {}

    def add(key: str, title: str, detail: str, points: int, severity: str = "medium"):
        if key not in findings:
            findings[key] = {"id": key, "title": title, "detail": detail, "points": points, "severity": severity}

    for page_index, page in enumerate(pages):
        page_url = str(page.get("url", "unknown page"))
        for finding in page.get("findings", []):
            lower = str(finding).lower()
            if "password input" in lower:
                add("page-password-form", "Password form observed", f"{page_url}: {finding}", 18, "high")
            elif "form action(s) point" in lower:
                add("page-external-form", "Form submits to another hostname", f"{page_url}: {finding}", 16, "high")
            elif "hidden iframe" in lower:
                add("page-hidden-iframe", "Hidden iframe observed", f"{page_url}: {finding}", 14, "high")
            elif "uses http" in lower:
                add("page-http", "Unencrypted HTTP page", f"{page_url}: {finding}", 8, "low")
            elif "http response status" in lower:
                add(f"http-error-{page_index}", "HTTP response status needs review", f"{page_url}: {finding}", 3, "low")
            elif "security headers were not observed" in lower:
                add("page-security-headers", "Common browser security headers missing", f"{page_url}: {finding}", 4, "low")
            elif "strict-transport-security" in lower:
                add("page-hsts", "HSTS header not observed", f"{page_url}: {finding}", 2, "low")
            elif "iframe(s)" in lower:
                add("page-iframe", "Iframe observed", f"{page_url}: {finding}", 5, "low")
    signals = list(findings.values())
    score = min(100, sum(x["points"] for x in signals))
    verdict = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "INCONCLUSIVE"
    if not signals:
        signals = [{"id": "no-scored-live-signals", "title": "No scored page indicators", "detail": "The bounded inspector did not detect scored indicators in the fetched pages. This does not establish trustworthiness.", "points": 0, "severity": "info"}]
    result.update({
        "id": result.get("id") or uuid.uuid4().hex[:16],
        "verdict": verdict,
        "risk_score": score,
        "risk_level": "high" if score >= 60 else "medium" if score >= 30 else "low",
        "signals": signals,
        "signal_count": len([x for x in signals if x["points"] > 0]),
        "recommendation": "Review the observed HTML, redirects, form destinations and headers. Missing headers/forms are context signals, not proof of phishing. Verify reputation with approved threat-intelligence sources.",
    })
    return result

