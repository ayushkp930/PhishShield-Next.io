"""Public DNS and TLS metadata for a bounded defensive URL investigation.

DNS queries are sent to Cloudflare's public DNS-over-HTTPS endpoint. TLS sockets connect
only to IP addresses resolved and validated as globally routable; the hostname is retained
for SNI and certificate verification. This module does not fetch HTML or execute page code.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .analyzer import analyze_url
from .intel import registrable_domain

DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
DNS_TIMEOUT = httpx.Timeout(5.0, connect=3.0)
MAX_RECORDS_PER_TYPE = 20
MAX_RECORD_LENGTH = 512
CT_TIMEOUT = httpx.Timeout(7.0, connect=3.0)
MAX_CT_RESULTS = 50


def _global_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not (ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def _record_value(record: dict) -> str:
    value = str(record.get("data") or "").strip()
    if record.get("type") == 16:  # TXT: return a readable value without shell-like parsing.
        value = value.replace('" "', '').strip('"')
    return value[:MAX_RECORD_LENGTH]


async def _query_dns(client: httpx.AsyncClient, name: str, record_type: str) -> dict:
    try:
        response = await client.get(DNS_ENDPOINT, params={"name": name, "type": record_type}, headers={"accept": "application/dns-json"})
        if response.status_code != 200:
            return {"status": "error", "records": [], "message": f"DNS resolver returned HTTP {response.status_code}."}
        data = response.json()
        rcode = data.get("Status")
        answers = data.get("Answer") or []
        records = []
        for answer in answers[:MAX_RECORDS_PER_TYPE]:
            if not isinstance(answer, dict):
                continue
            records.append(_record_value(answer))
        if records:
            status = "record_found"
            message = f"{len(records)} answer(s) returned."
        elif rcode == 3:
            status, message = "nxdomain", "The queried DNS name does not exist according to this resolver."
        elif rcode == 0:
            status, message = "no_records", "No records of this type were returned."
        else:
            status, message = "dns_error", f"DNS response code {rcode}."
        return {"status": status, "records": records, "message": message, "ttl_min_seconds": min((int(x.get("TTL") or 0) for x in answers if isinstance(x, dict)), default=None)}
    except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
        return {"status": "unavailable", "records": [], "message": "DNS-over-HTTPS lookup failed or timed out."}


async def lookup_dns_records(target: str) -> dict:
    """Retrieve bounded public DNS records for a normalized URL/domain."""
    base = analyze_url(target)
    parts = urlsplit(base["normalized_url"])
    hostname = (parts.hostname or "").strip("[]").rstrip(".").lower()
    if not hostname:
        raise ValueError("A hostname is required for DNS lookup.")
    try:
        ipaddress.ip_address(hostname)
        return {"status": "ip_literal", "hostname": hostname, "registrable_domain": hostname, "resolver": "Cloudflare DNS-over-HTTPS", "records": {}, "message": "The target is an IP literal, so domain DNS record queries were skipped."}
    except ValueError:
        pass
    domain = registrable_domain(hostname)
    query_list = [(record_type, hostname) for record_type in DNS_TYPES]
    # Also query DMARC at the registrable domain; SPF is present in the TXT result when published.
    query_list.append(("TXT", f"_dmarc.{domain}"))
    async with httpx.AsyncClient(timeout=DNS_TIMEOUT, follow_redirects=False, headers={"user-agent": "PhishShield-Next/3.2 (public DNS metadata)"}) as client:
        results = await asyncio.gather(*(_query_dns(client, name, kind) for kind, name in query_list), return_exceptions=True)
    records: dict[str, dict] = {}
    for (kind, name), result in zip(query_list, results):
        key = "DMARC_TXT" if name.startswith("_dmarc.") else kind
        if isinstance(result, BaseException):
            records[key] = {"status": "unavailable", "records": [], "message": "DNS lookup failed."}
        else:
            result["queried_name"] = name
            records[key] = result
    ipv4 = records.get("A", {}).get("records", [])
    ipv6 = records.get("AAAA", {}).get("records", [])
    private_answers = [x for x in (ipv4 + ipv6) if not _global_ip(x)]
    return {
        "status": "record_found" if any(v.get("records") for v in records.values()) else "no_records",
        "hostname": hostname,
        "registrable_domain": domain,
        "resolver": "Cloudflare DNS-over-HTTPS (1.1.1.1)",
        "records": records,
        "address_summary": {"ipv4": ipv4, "ipv6": ipv6, "non_public_answers_observed": bool(private_answers)},
        "email_auth_summary": {
            "spf_records": [x for x in records.get("TXT", {}).get("records", []) if x.lower().startswith("v=spf1")],
            "dmarc_records": records.get("DMARC_TXT", {}).get("records", []),
        },
        "limitations": [
            "DNS is time-sensitive and resolver/cache dependent; absent records do not imply phishing.",
            "TXT records may contain public verification strings; review before sharing the report.",
            "DNS queries disclose the queried hostname to the selected public resolver.",
        ],
    }



async def lookup_certificate_transparency(target: str) -> dict:
    """Query public certificate-transparency entries for a registrable domain.

    This asks crt.sh for already-published certificate records; it does not submit a
    certificate or contact the web target. Results can be delayed, duplicated, or partial.
    """
    base = analyze_url(target)
    parts = urlsplit(base["normalized_url"])
    hostname = (parts.hostname or "").strip("[]").rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
        return {"status": "skipped", "hostname": hostname, "summary": "Certificate transparency search requires a domain name, not an IP literal.", "entries": []}
    except ValueError:
        pass
    if hostname == "localhost" or hostname.endswith((".local", ".internal", ".test", ".invalid", ".example")) or "." not in hostname:
        return {"status": "skipped", "hostname": hostname, "summary": "Certificate transparency search requires a public registered domain.", "entries": []}
    domain = registrable_domain(hostname)
    try:
        async with httpx.AsyncClient(timeout=CT_TIMEOUT, follow_redirects=False, headers={"User-Agent": "PhishShield-Next/3.2 (public CT metadata)", "Accept": "application/json"}) as client:
            response = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        if response.status_code == 404:
            return {"status": "no_match", "hostname": hostname, "domain": domain, "entries": [], "summary": "No CT entries were returned by crt.sh for this query."}
        if response.status_code != 200:
            return {"status": "error", "hostname": hostname, "domain": domain, "entries": [], "summary": f"Certificate transparency service returned HTTP {response.status_code}."}
        if len(response.content) > 2_000_000:
            return {"status": "truncated", "hostname": hostname, "domain": domain, "entries": [], "summary": "The CT response exceeded the 2 MB safety cap and was not parsed."}
        data = response.json()
        if not isinstance(data, list):
            return {"status": "error", "hostname": hostname, "domain": domain, "entries": [], "summary": "The CT service returned an unexpected response format."}
    except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
        return {"status": "unavailable", "hostname": hostname, "domain": domain, "entries": [], "summary": "Certificate transparency lookup failed or timed out."}

    # Deduplicate repeated issuer/precertificate rows and keep details to a bounded result set.
    seen = set()
    entries = []
    for row in data:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("id") or ""), str(row.get("not_before") or ""), str(row.get("common_name") or ""))
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "id": str(row.get("id") or "")[:80],
            "logged_at": str(row.get("entry_timestamp") or "")[:80],
            "not_before": str(row.get("not_before") or "")[:80],
            "not_after": str(row.get("not_after") or "")[:80],
            "common_name": str(row.get("common_name") or "")[:253],
            "name_value": str(row.get("name_value") or "")[:1500],
            "issuer_name": str(row.get("issuer_name") or "")[:500],
        })
        if len(entries) >= MAX_CT_RESULTS:
            break
    return {
        "status": "record_found" if entries else "no_match",
        "hostname": hostname, "domain": domain, "source": "crt.sh (public certificate-transparency search)",
        "count_returned": len(entries), "results_truncated": len(data) > MAX_CT_RESULTS, "entries": entries,
        "summary": f"Returned {len(entries)} distinct certificate record(s) for {domain}; CT entries show certificate issuance history, not whether a site is safe.",
        "limitations": ["Certificate-transparency logs can contain delayed, duplicated, expired, or misissued certificates.", "A certificate entry or absence of entries is not a phishing verdict."],
    }

def _flatten_name(parts) -> str:
    out = []
    for component in parts or ():
        try:
            key, value = component[0]
            out.append(f"{key}={value}")
        except (TypeError, IndexError, ValueError):
            continue
    return ", ".join(out)[:1000]


def _tls_lookup_sync(hostname: str, port: int) -> dict:
    try:
        address_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"status": "dns_failed", "hostname": hostname, "message": "Hostname could not be resolved for TLS inspection."}
    addresses = []
    for family, socktype, proto, _canon, sockaddr in address_info:
        ip = sockaddr[0]
        if not _global_ip(ip):
            return {"status": "blocked_non_public_resolution", "hostname": hostname, "message": "TLS inspection blocked because DNS returned a non-public destination."}
        item = (family, socktype, proto, ip)
        if item not in addresses:
            addresses.append(item)
    if not addresses:
        return {"status": "unavailable", "hostname": hostname, "message": "No public IP address was available for TLS inspection."}

    last_error = "connection_failed"
    for family, socktype, proto, ip in addresses[:3]:
        raw = None
        wrapped = None
        try:
            # Connect to the already-validated IP so a second DNS lookup cannot redirect the socket.
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(4.0)
            raw.connect((ip, port))
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(raw, server_hostname=hostname if not _is_ip_literal(hostname) else None)
            cert = wrapped.getpeercert() or {}
            der = wrapped.getpeercert(binary_form=True) or b""
            not_after = cert.get("notAfter")
            not_before = cert.get("notBefore")
            expiry_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc) if not_after else None
            start_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_before), tz=timezone.utc) if not_before else None
            now = datetime.now(timezone.utc)
            sans = [f"{kind}:{value}"[:260] for kind, value in cert.get("subjectAltName", ())[:100]]
            return {
                "status": "certificate_verified",
                "hostname": hostname,
                "peer_ip": ip,
                "port": port,
                "certificate_verified": True,
                "subject": _flatten_name(cert.get("subject")),
                "issuer": _flatten_name(cert.get("issuer")),
                "subject_alt_names": sans,
                "serial_number": str(cert.get("serialNumber") or "")[:100],
                "version": cert.get("version"),
                "valid_from": start_dt.isoformat() if start_dt else None,
                "valid_until": expiry_dt.isoformat() if expiry_dt else None,
                "days_until_expiry": (expiry_dt - now).days if expiry_dt else None,
                "expired": bool(expiry_dt and expiry_dt < now),
                "not_yet_valid": bool(start_dt and start_dt > now),
                "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else None,
                "tls_version": wrapped.version(),
                "cipher": (wrapped.cipher() or [None])[0],
                "message": "TLS certificate validation succeeded for the requested hostname.",
                "limitations": ["This checks certificate trust/metadata only; it does not assess certificate transparency or all revocation signals."],
            }
        except ssl.SSLCertVerificationError:
            last_error = "certificate_verification_failed"
            # Collect metadata without trusting it. This is strictly reporting; the status remains invalid.
            try:
                if wrapped:
                    wrapped.close()
                    wrapped = None
                    raw = None
                raw2 = socket.socket(family, socktype, proto)
                raw2.settimeout(4.0)
                raw2.connect((ip, port))
                with ssl._create_unverified_context().wrap_socket(raw2, server_hostname=hostname if not _is_ip_literal(hostname) else None) as probe:
                    cert = probe.getpeercert() or {}
                    der = probe.getpeercert(binary_form=True) or b""
                    return {"status": "certificate_invalid", "hostname": hostname, "peer_ip": ip, "port": port,
                            "certificate_verified": False, "subject": _flatten_name(cert.get("subject")),
                            "issuer": _flatten_name(cert.get("issuer")),
                            "subject_alt_names": [f"{k}:{v}"[:260] for k, v in cert.get("subjectAltName", ())[:100]],
                            "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else None,
                            "message": "TLS certificate could not be verified. Untrusted certificate metadata is shown only as evidence."}
            except (OSError, ssl.SSLError):
                pass
            break
        except (OSError, ssl.SSLError, ValueError):
            last_error = "tls_handshake_failed"
        finally:
            if wrapped:
                try: wrapped.close()
                except OSError: pass
            elif raw:
                try: raw.close()
                except OSError: pass
    message = "The TLS certificate could not be verified." if last_error == "certificate_verification_failed" else "TLS connection failed or timed out."
    return {"status": last_error, "hostname": hostname, "port": port, "certificate_verified": False, "message": message}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


async def lookup_tls_certificate(target: str) -> dict:
    parsed = analyze_url(target)
    parts = urlsplit(parsed["normalized_url"])
    hostname = (parts.hostname or "").strip("[]").rstrip(".").lower()
    if parts.scheme.lower() != "https":
        return {"status": "not_https", "hostname": hostname, "certificate_verified": False, "message": "The target uses HTTP; no TLS certificate is presented on the supplied URL."}
    port = parts.port or 443
    if port != 443:
        return {"status": "unsupported_port", "hostname": hostname, "port": port, "certificate_verified": False, "message": "TLS metadata is only collected from standard HTTPS port 443."}
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if hostname == "localhost" or hostname.endswith((".local", ".internal", ".test", ".invalid", ".example")):
            return {"status": "blocked_local_name", "hostname": hostname, "certificate_verified": False, "message": "TLS inspection blocked for local/test-only hostnames."}
    return await asyncio.wait_for(asyncio.to_thread(_tls_lookup_sync, hostname, port), timeout=10)


async def inspect_network_metadata(target: str) -> dict:
    """Collect public DNS records and TLS metadata; does not crawl HTTP pages."""
    base = analyze_url(target)
    parts = urlsplit(base["normalized_url"])
    hostname = (parts.hostname or "").strip("[]").rstrip(".").lower()
    dns_task = lookup_dns_records(target)
    tls_task = lookup_tls_certificate(target)
    ct_task = lookup_certificate_transparency(target)
    dns, tls, ct = await asyncio.gather(dns_task, tls_task, ct_task, return_exceptions=True)
    if isinstance(dns, BaseException):
        dns = {"status": "error", "hostname": hostname, "records": {}, "message": f"DNS metadata unavailable ({type(dns).__name__})."}
    if isinstance(tls, BaseException):
        tls = {"status": "error", "hostname": hostname, "certificate_verified": False, "message": f"TLS metadata unavailable ({type(tls).__name__})."}
    if isinstance(ct, BaseException):
        ct = {"status": "error", "hostname": hostname, "entries": [], "summary": f"CT metadata unavailable ({type(ct).__name__})."}
    return {"dns": dns, "tls": tls, "certificate_transparency": ct}
