"""Optional threat-intelligence enrichments and WHOIS/RDAP metadata.

Provider secrets are read only from backend environment variables. No submitted URL is fetched
by this module; provider lookups are explicitly invoked by an API or CLI command.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import socket
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, parse_qsl

import httpx

from .analyzer import analyze_url

USER_AGENT = "PhishShield-Next/3.2 (defensive security triage; contact: project maintainer)"
TIMEOUT = httpx.Timeout(9.0, connect=4.0)
_SENSITIVE_QUERY_KEYS = re.compile(
    r"(?:^|_)(?:token|access.?token|refresh.?token|secret|password|passwd|session|auth|authorization|"
    r"reset|invite|invitation|verification|verify|otp|code|signature|sig|api.?key|private.?key|jwt|email)(?:$|_)",
    re.I,
)
# A small common-suffix list handles frequent multi-label public suffixes without a downloaded PSL.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in", "com.br", "com.cn",
    "com.sg", "com.my", "com.mx", "com.tr", "co.nz", "co.jp", "co.kr", "com.tw",
    "com.hk", "com.ar", "com.pl", "co.za", "com.de", "com.fr", "com.es", "com.it",
}


def _api_key(name: str) -> str:
    return os.getenv(name, "").strip()


def _normalise_target(target: str) -> tuple[str, str, str]:
    result = analyze_url(target)
    url = result["normalized_url"]
    parts = urlsplit(url)
    hostname = (parts.hostname or "").strip("[]").rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname could not be normalised.") from exc
    if not hostname or len(hostname) > 253:
        raise ValueError("Enter a valid domain or URL.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("External reputation lookups are blocked for private, loopback, link-local, and reserved IP addresses.")
    if address is None and (hostname == "localhost" or hostname.endswith((".local", ".internal", ".test", ".invalid"))):
        raise ValueError("External reputation lookups are blocked for local/internal/test-only hostnames.")
    return url, hostname, parts.query


def has_sensitive_query(target: str) -> bool:
    """Reject common secrets/tokens in query keys before sharing with third parties."""
    try:
        parts = urlsplit(target if "://" in target else "https://" + target)
    except ValueError:
        return False
    try:
        params = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=150)
    except ValueError:
        # A malformed/excessively fragmented query should not be sent to external services.
        return True
    for key, _value in params:
        key_norm = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if _SENSITIVE_QUERY_KEYS.search(key_norm):
            return True
    return False


def registrable_domain(hostname: str) -> str:
    """Best-effort registered domain for WHOIS/RDAP; not a full public-suffix implementation."""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = [x for x in hostname.split(".") if x]
    if len(labels) < 2:
        return hostname
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def _provider(status: str, summary: str, **extra) -> dict:
    return {"status": status, "summary": summary, **extra}


def _http_error(response: httpx.Response) -> dict:
    if response.status_code == 404:
        return _provider("not_found", "No existing record was found for this indicator.")
    if response.status_code == 429:
        return _provider("rate_limited", "The provider rate limit was reached; retry later.")
    if response.status_code in (401, 403):
        return _provider("auth_error", "The provider rejected the key or this account lacks API access.")
    return _provider("error", f"Provider returned HTTP {response.status_code}.")


async def _get_json(url: str, *, headers: dict | None = None, params: dict | None = None) -> tuple[httpx.Response | None, dict | None]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}) as client:
            response = await client.get(url, headers=headers, params=params)
        try:
            data = response.json()
        except ValueError:
            data = None
        return response, data if isinstance(data, dict) else None
    except (httpx.HTTPError, asyncio.TimeoutError):
        return None, None


async def _post_form_json(url: str, *, headers: dict, data: dict) -> tuple[httpx.Response | None, dict | None]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}) as client:
            response = await client.post(url, headers=headers, data=data)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        return response, payload if isinstance(payload, dict) else None
    except (httpx.HTTPError, asyncio.TimeoutError):
        return None, None


async def _post_json(url: str, *, headers: dict, json_body: dict) -> tuple[httpx.Response | None, dict | None]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"}) as client:
            response = await client.post(url, headers=headers, json=json_body)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        return response, payload if isinstance(payload, dict) else None
    except (httpx.HTTPError, asyncio.TimeoutError):
        return None, None


async def check_virustotal(url: str, *, submit_if_missing: bool = False) -> dict:
    key = _api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return _provider("not_configured", "VIRUSTOTAL_API_KEY is not configured on the backend.")
    # VirusTotal URL IDs are URL-safe base64 without padding; fresh submission is an explicit opt-in below.
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    response, data = await _get_json(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": key},
    )
    if response is None:
        return _provider("unavailable", "VirusTotal could not be reached or timed out.")
    # An unknown URL can optionally be submitted for a new analysis, but this must be
    # explicitly requested by the user. VirusTotal documents that queried/submitted
    # indicators may become part of its community dataset; never enable this implicitly.
    if response.status_code == 404 and submit_if_missing:
        submit_response, submit_data = await _post_form_json(
            "https://www.virustotal.com/api/v3/urls", headers={"x-apikey": key}, data={"url": url}
        )
        if submit_response is None:
            return _provider("unavailable", "VirusTotal URL submission could not be reached or timed out.")
        if submit_response.status_code not in (200, 201) or not submit_data:
            return _http_error(submit_response)
        analysis_id = str((submit_data.get("data") or {}).get("id") or "")
        if not analysis_id:
            return _provider("submitted", "VirusTotal accepted the URL but did not return an analysis identifier.", submitted=True)
        analysis_status = "queued"
        # Bounded polling only; do not hammer provider quotas waiting for a scan.
        for _ in range(3):
            await asyncio.sleep(1.5)
            analysis_response, analysis_data = await _get_json(
                f"https://www.virustotal.com/api/v3/analyses/{quote(analysis_id, safe='')}",
                headers={"x-apikey": key},
            )
            if analysis_response is None or analysis_response.status_code != 200 or not analysis_data:
                break
            analysis_status = str(((analysis_data.get("data") or {}).get("attributes") or {}).get("status") or "queued")
            if analysis_status == "completed":
                break
        # Prefer the cached URL report after submission; it usually contains the full engine results.
        if analysis_status == "completed":
            response, data = await _get_json(
                f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key}
            )
        else:
            return _provider(
                "submitted", "VirusTotal accepted a fresh analysis request; processing is still pending. Re-run the investigation shortly to fetch the completed report.",
                submitted=True, analysis_id=analysis_id,
                analysis_url=f"https://www.virustotal.com/gui/analyses/{quote(analysis_id, safe='')}",
                analysis_status=analysis_status,
                report_url=f"https://www.virustotal.com/gui/url/{url_id}",
            )
    if response is None:
        return _provider("unavailable", "VirusTotal could not be reached or timed out.")
    if response.status_code != 200 or not data:
        return _http_error(response)
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
    all_engine_results = []
    detections = []
    raw_results = attrs.get("last_analysis_results") or {}
    for engine, record in raw_results.items():
        if not isinstance(record, dict):
            continue
        normalized = {
            "engine": str(engine)[:120],
            "category": str(record.get("category") or "unknown")[:40],
            "result": str(record.get("result") or "")[:240],
            "method": str(record.get("method") or "")[:80],
            "engine_version": str(record.get("engine_version") or "")[:80],
            "engine_update": str(record.get("engine_update") or "")[:80],
        }
        all_engine_results.append(normalized)
        if isinstance(record, dict) and record.get("category") in {"malicious", "suspicious"}:
            detections.append(normalized)
    provider_status = "threat_found" if malicious > 0 or suspicious > 0 else "no_match"
    return _provider(
        provider_status, f"{malicious} malicious and {suspicious} suspicious detection(s) across {total} reported engine result(s). No-match is not proof of safety.",
        malicious=malicious, suspicious=suspicious, harmless=int(stats.get("harmless") or 0), undetected=int(stats.get("undetected") or 0),
        engine_results=total, detections=detections[:200],
        all_engine_results=all_engine_results[:200], all_engine_results_truncated=len(all_engine_results) > 200,
        last_analysis_date=attrs.get("last_analysis_date"),
        last_submission_date=attrs.get("last_submission_date"),
        times_submitted=attrs.get("times_submitted"),
        last_http_response_code=attrs.get("last_http_response_code"),
        last_final_url=str(attrs.get("last_final_url") or "")[:2048] or None,
        title=str(attrs.get("title") or "")[:300] or None,
        categories={str(k)[:80]: str(v)[:160] for k, v in (attrs.get("categories") or {}).items() if isinstance(k, str) and v is not None},
        tags=[str(x)[:120] for x in (attrs.get("tags") or [])[:100]],
        reputation=attrs.get("reputation") if isinstance(attrs.get("reputation"), (int, float)) else None,
        total_votes={str(k)[:80]: int(v) for k, v in (attrs.get("total_votes") or {}).items() if isinstance(v, (int, float))},
        report_url=f"https://www.virustotal.com/gui/url/{url_id}",
    )


async def check_webrisk(url: str) -> dict:
    key = _api_key("GOOGLE_WEB_RISK_API_KEY")
    if not key:
        return _provider("not_configured", "GOOGLE_WEB_RISK_API_KEY is not configured on the backend.")
    response, data = await _get_json(
        "https://webrisk.googleapis.com/v1/uris:search",
        params={"key": key, "uri": url, "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"]},
    )
    if response is None:
        return _provider("unavailable", "Google Web Risk could not be reached or timed out.")
    if response.status_code != 200 or data is None:
        return _http_error(response)
    threat = data.get("threat") or {}
    types = sorted(set(str(x) for x in threat.get("threatTypes", []) if x))
    if types:
        return _provider("threat_found", "Matched Google Web Risk threat list(s): " + ", ".join(types) + ".", threat_types=types, expire_time=threat.get("expireTime"))
    return _provider("no_match", "No match in the queried Web Risk lists; this is not proof that the URL is safe.", threat_types=[])


async def check_urlscan(hostname: str, *, target_url: str = "", submit_fresh_scan: bool = False) -> dict:
    key = _api_key("URLSCAN_API_KEY")
    if not key:
        return _provider("not_configured", "URLSCAN_API_KEY is not configured on the backend.")
    # Search previous scan records. A fresh scan is a separate explicit user opt-in.
    response, data = await _get_json(
        "https://urlscan.io/api/v1/search/",
        headers={"API-Key": key},
        params={"q": f"domain:{hostname}", "size": "10"},
    )
    if response is None:
        return _provider("unavailable", "URLScan.io could not be reached or timed out.")
    if response.status_code != 200 or data is None:
        history = _http_error(response)
        history.update({"historical_count": 0, "historical_results": [], "new_scan": {"status": "not_requested"}})
        return history
    results = []
    for item in data.get("results") or []:
        task = item.get("task") or {}
        page = item.get("page") or {}
        verdicts = item.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        urlscan_verdict = verdicts.get("urlscan") or {}
        results.append({
            "scan_id": str(item.get("_id") or task.get("uuid") or "")[:100],
            "url": str(task.get("url") or page.get("url") or "")[:2048],
            "title": str(page.get("title") or "")[:200],
            "time": str(task.get("time") or "")[:80],
            "visibility": str(task.get("visibility") or "")[:20],
            "malicious": bool(overall.get("malicious") or urlscan_verdict.get("malicious")),
            "overall_score": overall.get("score"),
            "result_url": ("https://urlscan.io/result/" + quote(str(item.get("_id")), safe="")) if item.get("_id") else "",
        })
    count = data.get("total")
    count = count if isinstance(count, int) else len(results)
    found_malicious = any(x.get("malicious") for x in results)
    status = "threat_found" if found_malicious else ("record_found" if results else "no_match")
    new_scan = {"status": "not_requested", "summary": "No new URLScan submission was requested."}
    if submit_fresh_scan:
        if not target_url:
            new_scan = {"status": "error", "summary": "No complete URL was provided for a fresh URLScan submission."}
        else:
            submit_response, submit_data = await _post_json(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": key},
                json_body={"url": target_url, "visibility": "private", "tags": ["phishshield-next"]},
            )
            if submit_response is None:
                new_scan = {"status": "unavailable", "summary": "URLScan private-scan submission could not be reached or timed out."}
            elif submit_response.status_code not in (200, 201, 202) or not submit_data:
                err = _http_error(submit_response)
                new_scan = {"status": err.get("status", "error"), "summary": err.get("summary", "URLScan rejected the private scan request."), "visibility": "private"}
            else:
                scan_id = str(submit_data.get("uuid") or "")[:100]
                visibility = str(submit_data.get("visibility") or "private")[:20]
                result_url = ("https://urlscan.io/result/" + quote(scan_id, safe="")) if scan_id else ""
                scan_result = None
                # Poll for a short, bounded interval. If processing is still pending the report says so.
                if scan_id:
                    # URLScan recommends allowing processing time before polling. Keep this bounded
                    # so the combined endpoint can return a clear pending state instead of hanging.
                    await asyncio.sleep(10.0)
                    for poll_index in range(3):
                        poll_response, poll_data = await _get_json(
                            f"https://urlscan.io/api/v1/result/{quote(scan_id, safe='')}/",
                            headers={"API-Key": key},
                        )
                        if poll_response is not None and poll_response.status_code == 200 and isinstance(poll_data, dict):
                            scan_result = poll_data
                            break
                        if poll_response is not None and poll_response.status_code not in (404, 429):
                            break
                        if poll_index < 2:
                            await asyncio.sleep(2.0)
                if scan_result:
                    page = scan_result.get("page") or {}
                    verdicts = scan_result.get("verdicts") or {}
                    overall = verdicts.get("overall") or {}
                    urlscan_v = verdicts.get("urlscan") or {}
                    stats = scan_result.get("stats") or {}
                    lists = scan_result.get("lists") or {}
                    scan_details = {
                        "title": str(page.get("title") or "")[:300],
                        "url": str(page.get("url") or target_url)[:2048],
                        "domain": str(page.get("domain") or "")[:253],
                        "ip": str(page.get("ip") or "")[:80],
                        "country": str(page.get("country") or "")[:80],
                        "asn": str(page.get("asn") or "")[:150],
                        "server": str(page.get("server") or "")[:200],
                        "mime_type": str(page.get("mimeType") or "")[:150],
                        "overall_malicious": bool(overall.get("malicious") or urlscan_v.get("malicious")),
                        "overall_score": overall.get("score"),
                        "requests": stats.get("requests"),
                        "data_length": stats.get("dataLength"),
                        "domains_observed": [str(x)[:253] for x in (lists.get("domains") or [])[:100]],
                        "ips_observed": [str(x)[:80] for x in (lists.get("ips") or [])[:100]],
                        "trackers_observed": [str(x)[:253] for x in (lists.get("trackers") or [])[:100]],
                        "result_url": result_url,
                    }
                    new_scan = {"status": "completed", "summary": "URLScan private scan completed; see the provider result and extracted metadata.", "scan_id": scan_id, "visibility": visibility, "result_url": result_url, "result": scan_details}
                    if scan_details["overall_malicious"]:
                        status = "threat_found"
                else:
                    new_scan = {"status": "submitted", "summary": "URLScan accepted the private scan; processing was not complete within the brief polling window. Re-run investigation or open the result later.", "scan_id": scan_id, "visibility": visibility, "result_url": result_url}
    summary = f"Found {count} historical URLScan result(s) for {hostname}. Historical results may be incomplete or stale."
    return _provider(
        status, summary, count=count, results=results,
        new_scan=new_scan, historical_count=count, historical_results=results,
        limitations=["Historical URLScan results can be stale or incomplete.", "Fresh URLScan scans execute the target in URLScan's remote browser and should only be requested for URLs you are authorized to share.", "Private visibility avoids public search listings but does not mean the provider never processes the URL."],
    )


async def _resolve_public_ip(hostname: str) -> str | None:
    try:
        direct = ipaddress.ip_address(hostname)
        return str(direct) if direct.is_global else None
    except ValueError:
        pass
    def resolve():
        try:
            records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            ips = sorted({row[4][0].split("%", 1)[0] for row in records})
            for raw in ips:
                try:
                    ip = ipaddress.ip_address(raw)
                    if ip.is_global:
                        return str(ip)
                except ValueError:
                    continue
        except (OSError, ValueError):
            return None
        return None
    try:
        return await asyncio.wait_for(asyncio.to_thread(resolve), timeout=3.5)
    except asyncio.TimeoutError:
        return None


async def check_abuseipdb(hostname: str) -> dict:
    key = _api_key("ABUSEIPDB_API_KEY")
    if not key:
        return _provider("not_configured", "ABUSEIPDB_API_KEY is not configured on the backend.")
    public_ip = await _resolve_public_ip(hostname)
    if not public_ip:
        return _provider("skipped", "No public IP address could be resolved; private/reserved IPs are never sent to AbuseIPDB.")
    response, data = await _get_json(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": public_ip, "maxAgeInDays": "90", "verbose": ""},
    )
    if response is None:
        return _provider("unavailable", "AbuseIPDB could not be reached or timed out.", ip_address=public_ip)
    if response.status_code != 200 or not data:
        return _http_error(response)
    item = data.get("data") or {}
    score = int(item.get("abuseConfidenceScore") or 0)
    total_reports = int(item.get("totalReports") or 0)
    summary = f"Abuse confidence {score}/100 with {total_reports} report(s) in the selected time window for {public_ip}."
    provider_status = "threat_found" if score >= 50 else ("no_match" if score == 0 and total_reports == 0 else "record_found")
    return _provider(
        provider_status, summary + " This score is provider-reported reputation, not a definitive verdict.", ip_address=public_ip, abuse_confidence_score=score, total_reports=total_reports,
        distinct_users=int(item.get("numDistinctUsers") or 0), last_reported_at=item.get("lastReportedAt"),
        country_code=item.get("countryCode"), country_name=item.get("countryName"), isp=item.get("isp"),
        usage_type=item.get("usageType"), domain=item.get("domain"), is_tor=bool(item.get("isTor")),
        is_whitelisted=item.get("isWhitelisted") if isinstance(item.get("isWhitelisted"), bool) else None,
        hostnames=[str(x)[:253] for x in (item.get("hostnames") or [])[:50]],
        report_url=f"https://www.abuseipdb.com/check/{quote(public_ip, safe=':')}",
    )


def _vcard_value(entity: dict) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) > 1 and isinstance(card[1], list)):
        return None
    for row in card[1]:
        if len(row) >= 4 and str(row[0]).lower() in {"fn", "org"}:
            value = row[3]
            if isinstance(value, list):
                value = " ".join(str(x) for x in value)
            if value:
                return str(value)[:200]
    return None


def _find_registrar(entities: list) -> str | None:
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        roles = {str(x).lower() for x in entity.get("roles", [])}
        if "registrar" in roles:
            value = _vcard_value(entity)
            if value:
                return value
        nested = _find_registrar(entity.get("entities") or [])
        if nested:
            return nested
    return None


async def lookup_whois_rdap(target: str) -> dict:
    try:
        _url, hostname, _query = _normalise_target(target)
    except ValueError as exc:
        raise
    try:
        ip = ipaddress.ip_address(hostname)
        if not ip.is_global:
            return _provider("skipped", "WHOIS/RDAP lookup is limited to public IPs and registered domains.", target=hostname, nameservers=[], statuses=[])
        endpoint = f"https://rdap.org/ip/{quote(str(ip), safe=':')}"
        query_kind = "IP RDAP"
        query_target = str(ip)
    except ValueError:
        query_target = registrable_domain(hostname)
        if "." not in query_target or query_target in {"localhost", "example.test", "invalid"}:
            return _provider("skipped", "A registrable public domain is required for WHOIS/RDAP lookup.", target=hostname, nameservers=[], statuses=[])
        endpoint = "https://rdap.org/domain/" + quote(query_target, safe="")
        query_kind = "WHOIS / RDAP"
    try:
        # rdap.org is a bootstrap service; its redirects lead to the relevant registry RDAP service.
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, max_redirects=5, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"}) as client:
            response = await client.get(endpoint)
        if response.status_code != 200:
            error = _http_error(response)
            return {**error, "target": query_target, "lookup_type": query_kind, "nameservers": [], "statuses": []}
        try:
            data = response.json()
        except ValueError:
            return _provider("error", "RDAP registry returned an unreadable response.", target=query_target, lookup_type=query_kind, nameservers=[], statuses=[])
    except (httpx.HTTPError, asyncio.TimeoutError):
        return _provider("unavailable", "WHOIS/RDAP service could not be reached or timed out.", target=query_target, lookup_type=query_kind, nameservers=[], statuses=[])

    events = {}
    for event in data.get("events") or []:
        action = str(event.get("eventAction") or "").lower()
        date = event.get("eventDate")
        if date and action:
            events[action] = str(date)[:80]
    nameservers = sorted({str(ns.get("ldhName") or ns.get("unicodeName") or "")[:253].lower() for ns in data.get("nameservers") or [] if isinstance(ns, dict) and (ns.get("ldhName") or ns.get("unicodeName"))})[:20]
    statuses = [str(x)[:100] for x in data.get("status") or []][:30]
    registrar = _find_registrar(data.get("entities") or [])
    title = data.get("ldhName") or data.get("name") or query_target
    event_rows = [{"action": str(e.get("eventAction") or "")[:100], "date": str(e.get("eventDate") or "")[:80]}
                  for e in (data.get("events") or []) if isinstance(e, dict) and (e.get("eventAction") or e.get("eventDate"))][:50]
    entity_roles = sorted({str(role)[:80] for e in (data.get("entities") or []) if isinstance(e, dict) for role in (e.get("roles") or [])})[:30]
    links = [{"rel": str(x.get("rel") or "")[:80], "href": str(x.get("href") or "")[:500], "type": str(x.get("type") or "")[:120]}
             for x in (data.get("links") or []) if isinstance(x, dict) and x.get("href")][:30]
    notices = [{"title": str(x.get("title") or "")[:200], "description": [str(y)[:500] for y in (x.get("description") or [])[:5]],
                "links": [{"href": str(z.get("href") or "")[:500], "rel": str(z.get("rel") or "")[:80]} for z in (x.get("links") or [])[:5] if isinstance(z, dict)]}
               for x in (data.get("notices") or []) if isinstance(x, dict)][:10]
    fields = {
        "target": query_target, "lookup_type": query_kind, "registered_name": str(title)[:253],
        "handle": str(data.get("handle") or "")[:150] or None,
        "object_class_name": str(data.get("objectClassName") or "")[:100] or None,
        "registrar": registrar, "created_at": events.get("registration") or events.get("registered"),
        "updated_at": events.get("last changed") or events.get("last update of RDAP database"),
        "expires_at": events.get("expiration") or events.get("expiry"),
        "events": event_rows, "nameservers": nameservers, "statuses": statuses,
        "dnssec_signed": bool((data.get("secureDNS") or {}).get("delegationSigned")) if isinstance(data.get("secureDNS"), dict) else None,
        "entity_roles": entity_roles, "notices": notices, "links": links,
        "rdap_url": str(response.url)[:500],
    }
    return _provider("record_found", f"RDAP registration/network metadata retrieved for {query_target}; registration metadata does not indicate whether the domain is malicious.", **fields)


async def lookup_reputation(target: str, *, submit_unknown_to_virustotal: bool = False, submit_urlscan_private: bool = False, include_whois: bool = True) -> dict:
    """Query configured reputation providers and optional WHOIS/RDAP metadata.

    Does not fetch the target page itself. A fresh VirusTotal URL submission or URLScan
    private scan occurs only when the caller explicitly opts in after collecting consent.
    The caller must enforce external-sharing consent before invoking this function.
    """
    url, hostname, _query = _normalise_target(target)
    if has_sensitive_query(url):
        raise ValueError("This URL appears to contain a token, password, invite/reset code, or other sensitive query parameter. Remove the query string and try a sanitized URL before external reputation checks.")
    tasks = {
        "virustotal": check_virustotal(url, submit_if_missing=submit_unknown_to_virustotal),
        "google_webrisk": check_webrisk(url),
        "urlscan": check_urlscan(hostname, target_url=url, submit_fresh_scan=submit_urlscan_private),
        "abuseipdb": check_abuseipdb(hostname),
    }
    if include_whois:
        tasks["whois"] = lookup_whois_rdap(url)
    # Every provider has its own timeout; one outage must not erase other provider results.
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    output = {}
    for name, result in zip(tasks.keys(), results):
        if isinstance(result, BaseException):
            output[name] = _provider("error", "This lookup failed; no provider error details or secret values were exposed.")
        else:
            output[name] = result
    configured = [name for name in ("virustotal", "google_webrisk", "urlscan", "abuseipdb") if output[name].get("status") != "not_configured"]
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "hostname": hostname,
        "external_data_shared": {
            "virustotal": ("full URL for cached report lookup" + (" and a fresh analysis submission" if submit_unknown_to_virustotal else "; no fresh submission requested") + "; queried/submitted indicators may be retained or shared by the provider"),
            "google_webrisk": "full URL for threat-list lookup",
            "urlscan": "hostname for historical search" + ("; full URL submitted for a fresh private remote-browser scan" if submit_urlscan_private else "; no fresh scan submitted"),
            "abuseipdb": "one public resolved IP address only, if available",
            "whois": "registered domain or public IP only, through RDAP",
        },
        "providers": {name: output[name] for name in ("virustotal", "google_webrisk", "urlscan", "abuseipdb")},
        "whois": output.get("whois", _provider("not_requested", "WHOIS/RDAP was not requested in this threat-intelligence pass.")),
        "configured_provider_count": len(configured),
        "limitations": [
            "A provider no-match result is not proof that the indicator is safe.",
            "Results depend on each provider's coverage, quota, freshness, and account tier.",
            "URLScan historical search is limited to returned records; a fresh private remote-browser scan is launched only when separately authorized.",
            "WHOIS/RDAP fields can be redacted, missing, cached, or unavailable.",
        ],
    }
