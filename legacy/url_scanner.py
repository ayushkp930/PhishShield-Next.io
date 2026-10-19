import asyncio
import os
import re
import base64
import csv
import httpx
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init
from urllib.parse import urlparse
from fpdf import FPDF

load_dotenv()
init(autoreset=True)

# All API Keys
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

# Exact SOC-approved model IDs only
GROQ_MODEL = "llama3-8b-8192"
GEMINI_MODEL = "gemini-1.5-flash"

WHITELIST_DOMAINS = {
    "google.com",
    "microsoft.com",
    "github.com",
    "linkedin.com",
    "youtube.com",
}

COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.in", "com.br", "com.mx",
}

URL_PATTERN = re.compile(r"(https?://[^\"\s<>']+|[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s<>']*)?)")
IOC_PATTERN = re.compile(r"https?://[^\s\"'<>]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", re.I)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OFFLINE_DATASET_DIRS = [BASE_DIR, os.path.join(BASE_DIR, "data")]
URL_COLUMN_CANDIDATES = {"url", "urls", "link", "website", "uri", "domain", "host"}
LABEL_COLUMN_CANDIDATES = {"label", "result", "class", "status", "target", "type", "is_phishing"}
TEXT_COLUMN_CANDIDATES = {"body", "text", "content", "subject", "message", "raw_email"}

_OFFLINE_CACHE = {
    "loaded": False,
    "malicious_urls": set(),
    "malicious_domains": set(),
    "sources": [],
}



def normalize_url(url):
    url = url.strip().strip('"<>')
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = f"http://{url}"
    return url.rstrip('/')


def extract_domain(url):
    try:
        parsed = urlparse(normalize_url(url))
        domain = parsed.netloc.lower()
        return domain[4:] if domain.startswith("www.") else domain
    except Exception:
        return ""


def extract_base_domain(url_or_domain):
    """Normalize domain so subdomains map to the registrable base domain."""
    domain = extract_domain(url_or_domain)
    if not domain:
        return ""

    domain = domain.strip().lower().strip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return domain

    suffix2 = ".".join(parts[-2:])
    suffix3 = ".".join(parts[-3:])
    if suffix2 in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return suffix3
    return suffix2


def _is_malicious_label(raw_label):
    text = str(raw_label or "").strip().lower()
    if text in {"1", "bad", "phishing", "malicious", "spam", "fraud", "blacklist", "suspicious"}:
        return True
    if text in {"0", "good", "safe", "ham", "legit", "benign", "whitelist"}:
        return False
    if "phish" in text or "malic" in text or "fraud" in text or "spam" in text:
        return True
    if "safe" in text or "benign" in text or "ham" in text:
        return False
    return False


def _extract_iocs_from_text(value):
    if value is None:
        return []
    text = str(value)
    found = IOC_PATTERN.findall(text)
    return [item.strip().strip("<>'\"") for item in found if item and len(item.strip()) > 3]


def _load_single_csv_dataset(csv_path):
    loaded_rows = 0
    ioc_count = 0
    url_hits = set()
    domain_hits = set()

    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return {"file": os.path.basename(csv_path), "rows": 0, "ioc": 0}

            lowered = {name.lower().strip(): name for name in reader.fieldnames if name}
            label_cols = [lowered[k] for k in lowered if k in LABEL_COLUMN_CANDIDATES]
            url_cols = [lowered[k] for k in lowered if k in URL_COLUMN_CANDIDATES]
            text_cols = [lowered[k] for k in lowered if k in TEXT_COLUMN_CANDIDATES]

            for row in reader:
                loaded_rows += 1

                is_malicious = False
                for label_col in label_cols:
                    if _is_malicious_label(row.get(label_col)):
                        is_malicious = True
                        break

                if not is_malicious:
                    continue

                row_iocs = []
                for url_col in url_cols:
                    row_iocs.extend(_extract_iocs_from_text(row.get(url_col)))

                if not row_iocs:
                    for text_col in text_cols:
                        row_iocs.extend(_extract_iocs_from_text(row.get(text_col)))

                for ioc in row_iocs:
                    nurl = normalize_url(ioc)
                    domain = extract_domain(ioc)
                    if nurl:
                        url_hits.add(nurl)
                        ioc_count += 1
                    if domain:
                        domain_hits.add(domain)
                        ioc_count += 1

    except Exception:
        return {"file": os.path.basename(csv_path), "rows": loaded_rows, "ioc": ioc_count}

    _OFFLINE_CACHE["malicious_urls"].update(url_hits)
    _OFFLINE_CACHE["malicious_domains"].update(domain_hits)
    return {"file": os.path.basename(csv_path), "rows": loaded_rows, "ioc": ioc_count}


def _ensure_offline_cache_loaded():
    if _OFFLINE_CACHE["loaded"]:
        return

    seen = set()
    source_stats = []
    for data_dir in OFFLINE_DATASET_DIRS:
        if not os.path.isdir(data_dir):
            continue
        for name in os.listdir(data_dir):
            if not name.lower().endswith(".csv"):
                continue
            csv_path = os.path.join(data_dir, name)
            if csv_path in seen:
                continue
            seen.add(csv_path)
            source_stats.append(_load_single_csv_dataset(csv_path))

    _OFFLINE_CACHE["sources"] = source_stats
    _OFFLINE_CACHE["loaded"] = True


def check_offline_datasets(url, domain):
    """Check all local CSV datasets for known malicious URL/domain indicators."""
    _ensure_offline_cache_loaded()

    clean_url = normalize_url(url)
    clean_domain = extract_domain(domain or url)

    url_match = clean_url in _OFFLINE_CACHE["malicious_urls"]
    domain_match = clean_domain in _OFFLINE_CACHE["malicious_domains"]

    return {
        "status": "malicious" if (url_match or domain_match) else "clean",
        "url_match": url_match,
        "domain_match": domain_match,
        "sources_loaded": len(_OFFLINE_CACHE["sources"]),
        "known_malicious_urls": len(_OFFLINE_CACHE["malicious_urls"]),
        "known_malicious_domains": len(_OFFLINE_CACHE["malicious_domains"]),
    }


def get_offline_cache_stats(preload=True):
    """Return offline dataset cache stats for startup/health reporting."""
    if preload:
        _ensure_offline_cache_loaded()

    return {
        "loaded": _OFFLINE_CACHE["loaded"],
        "sources_loaded": len(_OFFLINE_CACHE["sources"]),
        "known_malicious_urls": len(_OFFLINE_CACHE["malicious_urls"]),
        "known_malicious_domains": len(_OFFLINE_CACHE["malicious_domains"]),
    }


def detect_phishing_patterns(domain):
    """Local pattern-based phishing detection without AI API dependency"""
    risk_score = 0
    red_flags = []
    
    # Common brand typosquatting patterns
    typosquatting_patterns = {
        'paypa1': ('PayPal typosquatting (1 instead of l)', 50),
        'paypa!': ('PayPal typosquatting (! instead of l)', 50),
        'amaz0n': ('Amazon typosquatting (0 instead of o)', 45),
        'micro50ft': ('Microsoft typosquatting', 40),
        'app1e': ('Apple typosquatting', 45),
        'go0gle': ('Google typosquatting', 40),
        'f4cebook': ('Facebook typosquatting', 40),
    }
    
    domain_lower = domain.lower()
    for pattern, (description, points) in typosquatting_patterns.items():
        if pattern in domain_lower:
            risk_score += points
            red_flags.append(description)
    
    # Brand domain spoofing with different TLDs
    spoofing_patterns = {
        ('icloud', 'br'): ('Apple iCloud spoofing with .br TLD', 45),
        ('icloud', 'ru'): ('Apple iCloud spoofing with .ru TLD', 50),
        ('apple', 'br'): ('Apple spoofing with .br TLD', 40),
        ('apple', 'ru'): ('Apple spoofing with .ru TLD', 45),
        ('google', 'br'): ('Google spoofing with .br TLD', 35),
        ('facebook', 'br'): ('Facebook spoofing with .br TLD', 35),
        ('amazon', 'br'): ('Amazon spoofing with .br TLD', 35),
        ('microsoft', 'ru'): ('Microsoft spoofing with .ru TLD', 40),
    }
    
    for (brand, tld), (description, points) in spoofing_patterns.items():
        if brand in domain_lower and domain.endswith(f'.{tld}'):
            risk_score += points
            red_flags.append(description)
    
    # Suspicious TLD patterns for known brands
    suspicious_tlds = ['.ru', '.cn', '.kr', '.su', '.tk', '.ml']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        if any(brand in domain_lower for brand in ['paypal', 'paypa1', 'amazon', 'apple', 'google', 'microsoft', 'bank', 'admin']):
            risk_score += 20
            red_flags.append(f'Known brand with suspicious TLD: {[t for t in suspicious_tlds if domain.endswith(t)][0]}')
    
    # Alert/system/security keywords combined with suspicious domains or brands
    impersonation_keywords = ['alert', 'alert-system', 'admin', 'login', 'verify', 'confirm', 'update-security', 'security-check']
    for keyword in impersonation_keywords:
        if keyword in domain_lower:
            # Check for brands (real or typosquatted)
            brand_patterns = ['paypal', 'paypa1', 'bank', 'amazon', 'amaz0n', 'apple', 'app1e', 'google', 'go0gle', 'microsoft']
            if any(brand in domain_lower for brand in brand_patterns):
                risk_score += 35  # Increased from 25
                red_flags.append(f'Impersonation keyword "{keyword}" combined with brand domain')
                break
    
    # Suspicious domain patterns that commonly appear in phishing emails
    suspicious_combos = [
        ('mail.', 'paypa1', 'Spoofed mail server for PayPal phishing', 40),
        ('security', 'alert', 'False security alert domain', 30),
        ('verify', 'account', 'Account verification phishing', 25),
        ('confirm', 'identity', 'Identity confirmation phishing', 25),
    ]
    
    for part1, part2, description, points in suspicious_combos:
        if part1 in domain_lower and part2 in domain_lower:
            risk_score += points
            red_flags.append(description)
    
    # Verdict thresholds (lowered to catch more phishing)
    verdict = "SAFE"
    if risk_score >= 65:
        verdict = "PHISHING"
    elif risk_score >= 35:  # Lowered from 40
        verdict = "SUSPICIOUS"
    
    return verdict, risk_score, red_flags


def query_kaggle_online_intel(url, offline_data=None):
    domain = extract_domain(url)
    if not domain:
        return "unknown", "Unable to evaluate Kaggle threat intel for malformed URL."

    if offline_data:
        if offline_data.get("status") == "malicious":
            return "matched", "Offline Kaggle CSV intelligence match found for URL/domain."
        return "loaded", (
            f"Offline CSV intelligence loaded from {offline_data.get('sources_loaded', 0)} dataset(s), "
            f"{offline_data.get('known_malicious_urls', 0)} malicious URLs indexed."
        )

    return "unknown", "Offline dataset status unavailable"


def analyze_phishing_with_ai(url, domain):
    """Use Groq/Gemini AI for phishing detection (no timeout limits)"""
    if not GROQ_API_KEY and not GEMINI_API_KEY:
        return "unknown", 0, "No API keys configured"
    
    phishing_prompt = f"""You are a cybersecurity expert. Analyze this URL/domain for phishing indicators.

URL: {url}
Domain: {domain}

Evaluate and respond with ONLY this format (no other text):
VERDICT:[SAFE|SUSPICIOUS|PHISHING]
CONFIDENCE:[0-100]
FLAGS:[comma-separated indicators or 'none']

Examples of red flags:
- Domain typosquatting (e.g., 'paypa1' instead of 'paypal', 'br-icloud.com' spoofing Apple)
- Suspicious TLD combinations (e.g., '.com.br' with US brand)
- New/recently registered domains
- Domains with excessive hyphens or numbers
- Email-like domains used as URLs
- Urgent/fake verification language in URL parameters"""

    # Groq exact model only
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": phishing_prompt}],
                model=GROQ_MODEL,
                temperature=0.1,
                max_tokens=200
            )
            result = response.choices[0].message.content.strip()
            ai_verdict, ai_confidence, ai_flags = _parse_ai_response(result)
            if ai_verdict != "unknown":
                return ai_verdict, ai_confidence, ai_flags
        except Exception:
            pass
    
    # Gemini exact model only
    if GEMINI_API_KEY:
        try:
            from google import genai
            client = genai.Client(api_key=GEMINI_API_KEY)
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=phishing_prompt
            )
            result = response.text.strip()
            ai_verdict, ai_confidence, ai_flags = _parse_ai_response(result)
            if ai_verdict != "unknown":
                return ai_verdict, ai_confidence, ai_flags
        except Exception:
            pass
    
    return "unknown", 0, "AI unavailable - using pattern detection"


async def analyze_phishing_with_ai_async(url, domain):
    """Run AI phishing analysis without blocking the event loop."""
    return await asyncio.to_thread(analyze_phishing_with_ai, url, domain)


async def collect_all_threat_intelligence(url, domain):
    """Collect threat data from all sources in parallel and never short-circuit."""
    print(f"{Fore.CYAN}[*] Collecting threat intelligence from all sources in parallel...{Style.RESET_ALL}")

    threat_data = {
        "ai": {"verdict": "unknown", "confidence": 0, "flags": "N/A"},
        "vt": {"status": "unknown", "message": "No data"},
        "abuse": {"status": "unknown", "abuse_score": 0, "total_reports": 0},
        "urlscan": {"status": "unknown", "verdict": "unknown"},
        "domain": {"registrar": "N/A", "age": "N/A", "expiry": "N/A", "status": "unknown"},
        "pattern": {"verdict": "SAFE", "score": 0, "flags": []},
        "offline": {
            "status": "unknown",
            "url_match": False,
            "domain_match": False,
            "sources_loaded": 0,
            "known_malicious_urls": 0,
            "known_malicious_domains": 0,
        }
    }

    async with httpx.AsyncClient(timeout=None, follow_redirects=True) as client:
        tasks = {
            "ai": asyncio.create_task(analyze_phishing_with_ai_async(url, domain)),
            "vt": asyncio.create_task(get_vt_data_async(url, client)),
            "abuse": asyncio.create_task(get_abuseipdb_data_async(url, client)),
            "urlscan": asyncio.create_task(get_urlscan_data_async(url, client)),
            "domain": asyncio.create_task(get_domain_details_async(url, client)),
            "pattern": asyncio.create_task(asyncio.to_thread(detect_phishing_patterns, domain)),
            "offline": asyncio.create_task(asyncio.to_thread(check_offline_datasets, url, domain)),
        }

        keys = list(tasks.keys())
        results = await asyncio.gather(*(tasks[k] for k in keys), return_exceptions=True)

    for key, result in zip(keys, results):
        if isinstance(result, Exception):
            continue

        if key == "ai":
            threat_data["ai"]["verdict"], threat_data["ai"]["confidence"], threat_data["ai"]["flags"] = result
        elif key == "vt":
            threat_data["vt"]["status"], threat_data["vt"]["message"] = result
        elif key == "abuse":
            threat_data["abuse"] = result
        elif key == "urlscan":
            threat_data["urlscan"] = result
        elif key == "domain":
            threat_data["domain"] = result
        elif key == "pattern":
            verdict, score, flags = result
            threat_data["pattern"]["verdict"] = verdict
            threat_data["pattern"]["score"] = score
            threat_data["pattern"]["flags"] = flags
        elif key == "offline":
            threat_data["offline"] = result

    return threat_data


def final_reasoning_analysis(url, threat_data):
    """Use AI to analyze all collected threat intelligence and provide final reasoning"""
    print(f"\n{Fore.CYAN}[*] Running final reasoning analysis on all collected data...{Style.RESET_ALL}")
    
    # Prepare comprehensive threat summary
    summary = f"""You are a senior cybersecurity analyst. Based on the following threat intelligence from multiple sources, provide a final verdict on whether this URL is phishing.

URL: {url}

THREAT INTELLIGENCE DATA COLLECTED:
1. AI Analysis: {threat_data['ai']['verdict']} ({threat_data['ai']['confidence']}% confidence)
   Flags: {threat_data['ai']['flags']}

2. VirusTotal: {threat_data['vt']['status']} - {threat_data['vt']['message']}

3. AbuseIPDB: Score {threat_data['abuse'].get('abuse_score', 0)}% ({threat_data['abuse'].get('status', 'unknown')})
    Reports: {threat_data['abuse'].get('total_reports', 0)}

4. URLScan: {threat_data['urlscan'].get('verdict', 'unknown')}

5. Domain Registration:
   Registrar: {threat_data['domain']['registrar']}
   Age: {threat_data['domain']['age']}
   Expiry: {threat_data['domain']['expiry']}

6. Pattern Detection: {threat_data['pattern']['verdict']} (Score: {threat_data['pattern']['score']})
   Patterns: {', '.join(threat_data['pattern']['flags']) if threat_data['pattern']['flags'] else 'None'}

Based on ALL the above data sources, provide your final assessment:

RESPONSE FORMAT (ONLY):
FINAL_VERDICT:[SAFE|SUSPICIOUS|CRITICAL_PHISHING]
REASONING:[2-3 sentence explanation considering all sources]
CONFIDENCE:[0-100]
"""

    # Gemini exact model first
    if GEMINI_API_KEY:
        try:
            from google import genai
            client = genai.Client(api_key=GEMINI_API_KEY)
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=summary
            )
            result = response.text.strip()
            print(f"{Fore.GREEN}[+] Final Analysis ({GEMINI_MODEL}):{Style.RESET_ALL}")
            print(f"{result}\n")
            return result
        except Exception:
            pass
    
    # Fallback to Groq
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": summary}],
                model=GROQ_MODEL,
                temperature=0.2,
                max_tokens=500
            )
            result = response.choices[0].message.content.strip()
            print(f"{Fore.GREEN}[+] Final Analysis ({GROQ_MODEL}):{Style.RESET_ALL}")
            print(f"{result}\n")
            return result
        except Exception:
            pass

    return _build_professional_fallback_ai_report(url, threat_data)


def _build_professional_fallback_ai_report(url, threat_data):
    """Generate a professional SOC-style reasoning report when LLM APIs are unavailable."""
    ai = threat_data.get("ai", {})
    vt = threat_data.get("vt", {})
    abuse = threat_data.get("abuse", {})
    urlscan = threat_data.get("urlscan", {})
    domain = threat_data.get("domain", {})
    pattern = threat_data.get("pattern", {})
    offline = threat_data.get("offline", {})

    score = 0
    findings = []

    ai_verdict = str(ai.get("verdict", "unknown")).upper()
    if ai_verdict == "PHISHING":
        score += 35
        findings.append("AI heuristic verdict indicates phishing behavior.")
    elif ai_verdict == "SUSPICIOUS":
        score += 18
        findings.append("AI heuristic verdict indicates suspicious behavior.")

    vt_status = str(vt.get("status", "unknown")).lower()
    if vt_status == "malicious":
        score += 30
        findings.append(f"VirusTotal detection positive ({vt.get('message', 'malicious indicators')}).")
    elif vt_status == "unknown":
        findings.append("VirusTotal has no conclusive record for this target.")

    abuse_score = abuse.get("abuse_score", 0)
    if abuse_score > 75:
        score += 18
        findings.append(f"AbuseIPDB confidence is high ({abuse_score}%).")
    elif abuse_score > 25:
        score += 10
        findings.append(f"AbuseIPDB reports moderate abuse confidence ({abuse_score}%).")

    urlscan_verdict = str(urlscan.get("verdict", "unknown")).upper()
    if urlscan_verdict == "MALICIOUS":
        score += 22
        findings.append("URLScan verdict marked target as malicious.")

    pattern_score = int(pattern.get("score", 0) or 0)
    if pattern_score > 0:
        score += min(pattern_score // 4, 12)
        findings.append(f"Pattern engine detected phishing indicators (score={pattern_score}).")
        flags = pattern.get("flags") or []
        if flags:
            findings.append(f"Pattern flags: {', '.join(flags[:4])}.")

    if offline.get("status") == "malicious":
        score += 25
        findings.append("Offline intelligence datasets matched known malicious IOC(s).")

    rdap_hidden_or_unknown = (
        domain.get("status") == "unknown"
        or domain.get("registrar") in ("N/A", "", None)
        or domain.get("age") in ("N/A", "", None)
    )
    if vt_status == "unknown" and rdap_hidden_or_unknown:
        score += 15
        findings.append("Zero-day risk: VT unknown with hidden/incomplete WHOIS footprint.")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score >= 75:
        final_verdict = "CRITICAL_PHISHING"
        actions = [
            "Block the URL/domain immediately at secure web gateway and DNS layers.",
            "Isolate impacted endpoints and reset potentially exposed credentials.",
            "Hunt for related IOCs across email, proxy, DNS, and EDR telemetry.",
        ]
    elif score >= 45:
        final_verdict = "SUSPICIOUS"
        actions = [
            "Quarantine related emails and enforce user click-block policy.",
            "Monitor endpoint and identity logs for follow-on activity.",
            "Re-scan the target with online intel when APIs become available.",
        ]
    else:
        final_verdict = "LOW_RISK"
        actions = [
            "Keep target under watchlist and monitor telemetry for anomalies.",
            "Allow with caution if business-critical and verified by analyst.",
        ]

    confidence = max(55, min(95, score))
    executive = (
        "Automated fallback reasoning generated due to temporary AI oracle unavailability. "
        "Assessment is derived from correlated threat intelligence, offline IOC datasets, "
        "WHOIS posture, and phishing pattern analytics."
    )

    findings_text = "\n".join(f"- {item}" for item in findings[:7]) if findings else "- No significant indicators collected."
    actions_text = "\n".join(f"- {item}" for item in actions)

    return (
        f"FINAL_VERDICT:{final_verdict}\n"
        f"CONFIDENCE:{confidence}\n"
        f"EXECUTIVE_SUMMARY:{executive}\n"
        f"KEY_FINDINGS:\n{findings_text}\n"
        f"RESPONSE_ACTIONS:\n{actions_text}"
    )


def _parse_ai_response(response):
    """Parse AI response for verdict, confidence, and flags"""
    verdict = "unknown"
    confidence = 0
    flags = ""
    
    lines = response.split('\n')
    for line in lines:
        if 'VERDICT:' in line:
            v = line.split('VERDICT:')[1].strip().upper()
            if v in ['SAFE', 'SUSPICIOUS', 'PHISHING']:
                verdict = v
        elif 'CONFIDENCE:' in line:
            try:
                confidence = int(line.split('CONFIDENCE:')[1].strip().rstrip('%'))
            except:
                confidence = 0
        elif 'FLAGS:' in line:
            flags = line.split('FLAGS:')[1].strip()
    
    return verdict, confidence, flags



def format_report(report):
    ai_report = report.get('ai_report') or report.get('final_reasoning') or "AI report unavailable"

    lines = [
        "="*60,
        "PHISHSHIELD PRO | PROFESSIONAL THREAT ASSESSMENT REPORT",
        "="*60,
        "",
        "TARGET INFORMATION:",
        f"  URL/Domain: {report['target']}",
        f"  Verdict: {report['verdict']}",
        f"  Risk Score: {report['risk_score']}/100",
        "",
        "PHISHING ANALYSIS:",
        "  AI Report:",
    ]

    for line in str(ai_report).splitlines():
        clean_line = line.strip()
        if clean_line:
            lines.append(f"    {clean_line}")
    
    lines.extend([
        "",
        "THREAT INTELLIGENCE:",
        f"  VirusTotal Status: {report['virustotal']['status']} ({report['virustotal']['message']})",
    ])
    
    # Add AbuseIPDB data if available
    abuse_data = report.get('abuseipdb', {})
    if abuse_data.get('status') != 'unknown':
        lines.append(f"  AbuseIPDB Score: {abuse_data.get('abuse_score', 0)}% ({abuse_data.get('status', 'unknown')})")
    
    # Add URLScan data if available
    urlscan_data = report.get('urlscan', {})
    if urlscan_data.get('status') != 'unknown':
        lines.append(f"  URLScan Verdict: {urlscan_data.get('verdict', 'unknown')}")

    offline_data = report.get('offline_datasets', {})
    if offline_data:
        lines.append(
            f"  Offline Datasets: {offline_data.get('sources_loaded', 0)} loaded, "
            f"{offline_data.get('known_malicious_urls', 0)} malicious URLs indexed"
        )
        if offline_data.get('status') == 'malicious':
            lines.append("  Offline Match: URL/domain matched known malicious indicators")
    
    lines.extend([
        f"  Kaggle Threat Intel: {report['kaggle']['detail']}",
        "",
        "DOMAIN INFORMATION:",
        f"  Registrar: {report['domain']['registrar']}",
        f"  Registration Date: {report['domain']['age']}",
        f"  Expiration Date: {report['domain']['expiry']}",
        f"  Domain Age Risk: {report['domain']['status']}",
        "",
        "RECOMMENDATION:",
        f"  {report.get('recommendation', 'Monitor for suspicious activity')}",
        "",
        "="*60,
    ])
    return "\n".join(lines)


def save_text_report(report, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(format_report(report))
    print(f"{Fore.GREEN}[+] Report exported to {output_path}{Style.RESET_ALL}")


def save_pdf_report(report, output_path):
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "PHISHSHIELD PRO Threat Assessment", ln=True, align="C")
    pdf.set_font("Arial", size=11)
    pdf.ln(5)
    for line in format_report(report).splitlines():
        pdf.multi_cell(0, 8, line)
    pdf.output(output_path)
    print(f"{Fore.GREEN}[+] PDF report saved to {output_path}{Style.RESET_ALL}")


def display_report_menu(report):
    while True:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}\n=== REPORT OPTIONS ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}[1] View Executive Summary")
        print(f"{Fore.CYAN}[2] Export Text Report")
        print(f"{Fore.CYAN}[3] Export PDF Report")
        print(f"{Fore.RED}[4] Return to Main Menu")

        choice = input(f"{Fore.GREEN}[?] Choice: {Style.RESET_ALL}").strip()
        if choice == '1':
            print(f"\n{Fore.YELLOW}{format_report(report)}{Style.RESET_ALL}")
        elif choice == '2':
            filename = input(f"{Fore.WHITE}Text file name to save: {Style.RESET_ALL}").strip() or "phishshield_report.txt"
            save_text_report(report, filename)
        elif choice == '3':
            filename = input(f"{Fore.WHITE}PDF file name to save: {Style.RESET_ALL}").strip() or "phishshield_report.pdf"
            save_pdf_report(report, filename)
        elif choice == '4':
            return True
        else:
            print(f"{Fore.RED}Invalid choice. Try again.{Style.RESET_ALL}")

    return False


def get_domain_details(url):
    return asyncio.run(get_domain_details_async(url))


async def get_domain_details_async(url, client=None):
    details = {"status": "unknown", "age": "N/A", "registrar": "N/A", "expiry": "N/A"}
    try:
        domain = extract_domain(url)
        if not domain:
            return details

        if client is None:
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as local_client:
                response = await local_client.get(f"https://rdap.org/domain/{domain}")
        else:
            response = await client.get(f"https://rdap.org/domain/{domain}")

        if response.status_code != 200:
            return details

        res = response.json()
        details = _update_rdap_details(details, res)
        return details
    except Exception:
        return details


def _update_rdap_details(details, rdap):
    _set_rdap_registrar(details, rdap.get("entities", []))
    _set_rdap_events(details, rdap.get("events", []))
    return details


def _set_rdap_registrar(details, entities):
    for entity in entities:
        if "registrar" in str(entity.get("roles", [])).lower():
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and len(vcard[1]) > 3:
                details["registrar"] = vcard[1][3]


def _set_rdap_events(details, events):
    for event in events:
        date_str = event.get("eventDate", "")[:10]
        if event.get("eventAction") == "registration" and date_str:
            age_days = (datetime.now() - datetime.strptime(date_str, "%Y-%m-%d")).days
            details["age"] = f"{age_days} days (Reg: {date_str})"
            details["status"] = "suspicious" if age_days < 30 else "safe"
        if event.get("eventAction") == "expiration" and date_str:
            details["expiry"] = date_str


def get_vt_data(url):
    return asyncio.run(get_vt_data_async(url))


async def get_vt_data_async(url, client=None):
    if not VT_KEY:
        return "unknown", "API Key Missing"

    normalized = normalize_url(url)
    url_id = base64.urlsafe_b64encode(normalized.encode()).decode().strip("=")
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as local_client:
                res = await local_client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": VT_KEY},
                )
        else:
            res = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_KEY},
            )

        if res.status_code != 200:
            return "unknown", "No record found"
        data = res.json()
        malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        return ("malicious" if malicious > 0 else "safe"), f"{malicious} vendors flagged"
    except Exception:
        return "unknown", "No record found"


def get_abuseipdb_data(url):
    return asyncio.run(get_abuseipdb_data_async(url))


async def get_abuseipdb_data_async(url, client=None):
    """Query AbuseIPDB for domain/IP reputation."""
    fallback = {"status": "unknown", "abuse_score": 0, "total_reports": 0}
    if not ABUSEIPDB_KEY:
        return fallback

    try:
        domain = extract_domain(url)
        if not domain:
            return fallback

        if client is None:
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as local_client:
                res = await local_client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"domain": domain, "maxAgeInDays": 90},
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                )
        else:
            res = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"domain": domain, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )

        if res.status_code == 200:
            data = res.json()
            if "data" in data:
                abuse_score = data["data"].get("abuseConfidenceScore", 0)
                return {
                    "status": "high_risk" if abuse_score > 75 else "moderate" if abuse_score > 25 else "safe",
                    "abuse_score": abuse_score,
                    "total_reports": data["data"].get("totalReports", 0)
                }
    except Exception:
        pass

    return fallback


def get_urlscan_data(url):
    return asyncio.run(get_urlscan_data_async(url))


async def get_urlscan_data_async(url, client=None):
    """Query URLScan.io for detailed URL analysis."""
    fallback = {"status": "unknown", "verdict": "unknown"}
    if not URLSCAN_KEY:
        return fallback

    try:
        payload = {"url": url, "public": "off"}
        headers = {"API-Key": URLSCAN_KEY}
        if client is None:
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as local_client:
                res = await local_client.post("https://urlscan.io/api/v1/scan/", data=payload, headers=headers)
        else:
            res = await client.post("https://urlscan.io/api/v1/scan/", data=payload, headers=headers)

        if res.status_code in [200, 201]:
            data = res.json()
            uuid = data.get("uuid")
            if uuid:
                return {
                    "status": "submitted",
                    "uuid": uuid,
                    "verdict": "MALICIOUS" if data.get("verdict", {}).get("malicious", False) else "SAFE"
                }
    except Exception:
        pass

    return fallback


async def async_scan_url_master(url):
    clean_url = normalize_url(url)
    domain = extract_domain(clean_url)
    base_domain = extract_base_domain(clean_url)
    
    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== PHISHSHIELD PRO THREAT ASSESSMENT ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {clean_url}{Style.RESET_ALL}")

    if base_domain in WHITELIST_DOMAINS:
        print(f"{Fore.GREEN}[*] Domain verified in Global Whitelist. Bypassing deep scan to save API limits.{Style.RESET_ALL}")
        return {
            "target": clean_url,
            "verdict": "SAFE",
            "risk_score": 0,
            "kaggle": {"status": "whitelisted", "detail": "Whitelisted domain; deep scan skipped."},
            "offline_datasets": {
                "status": "whitelisted",
                "url_match": False,
                "domain_match": False,
                "sources_loaded": 0,
                "known_malicious_urls": 0,
                "known_malicious_domains": 0,
            },
            "domain": {
                "registrar": "N/A",
                "age": "N/A",
                "expiry": "N/A",
                "status": "whitelisted",
            },
            "virustotal": {"status": "whitelisted", "message": "Global whitelist bypass"},
            "abuseipdb": {"status": "whitelisted", "abuse_score": 0, "total_reports": 0},
            "urlscan": {"status": "whitelisted", "verdict": "SAFE"},
            "ai_analysis": {"verdict": "SAFE", "confidence": 100, "flags": "System Whitelisted Domain."},
            "ai_report": "System Whitelisted Domain.",
            "final_reasoning": "System Whitelisted Domain.",
            "recommendation": "Trusted global domain. No action required.",
        }

    # Collect all threat intelligence in parallel from all sources
    threat_data = await collect_all_threat_intelligence(clean_url, domain)
    
    # Run final reasoning analysis on all collected data
    print(f"{Fore.CYAN}[*] Performing comprehensive threat analysis...{Style.RESET_ALL}")
    final_analysis = await asyncio.to_thread(final_reasoning_analysis, clean_url, threat_data)
    
    # Extract verdict from final analysis
    ai_verdict = threat_data['ai']['verdict']
    ai_confidence = threat_data['ai']['confidence']
    ai_flags = threat_data['ai']['flags']
    
    v_status = threat_data['vt']['status']
    v_msg = threat_data['vt']['message']
    d_info = threat_data['domain']
    abuse_data = threat_data['abuse']
    urlscan_data = threat_data['urlscan']
    pattern_data = threat_data['pattern']
    offline_data = threat_data['offline']

    # Risk scoring with all intelligence sources
    risk_score = 0
    
    # AI/Pattern verdict scoring (highest priority)
    if ai_verdict == "PHISHING":
        risk_score += 85
    elif ai_verdict == "SUSPICIOUS":
        risk_score += 45
    elif ai_verdict == "SAFE":
        risk_score -= 15
    
    # Add threat intelligence from multiple sources
    if v_status == "malicious":
        risk_score += 70
    abuse_score = abuse_data.get('abuse_score', 0)
    if abuse_score > 75:
        risk_score += 50
    elif abuse_score > 25:
        risk_score += 25
    if urlscan_data['verdict'] == "MALICIOUS":
        risk_score += 60
    
    # Confidence boosts the verdict
    if ai_verdict != "unknown":
        risk_score += min(ai_confidence // 3, 15)
    
    if pattern_data['score'] > 0:
        risk_score += min(pattern_data['score'] // 4, 10)

    # Offline dataset intelligence boost (all CSV datasets)
    if offline_data.get('status') == 'malicious':
        risk_score += 55
    
    if d_info['status'] == "suspicious":
        risk_score += 20

    # Zero-day risk prevention: unknown VT + hidden/unavailable WHOIS is never auto-safe
    rdap_hidden_or_unknown = (
        d_info.get('status') == 'unknown'
        or d_info.get('registrar') in ('N/A', '', None)
        or d_info.get('age') in ('N/A', '', None)
    )
    zero_day_risk = (v_status == 'unknown' and rdap_hidden_or_unknown)
    if zero_day_risk:
        risk_score += 35

    if v_status == "safe" and ai_verdict == "SAFE":
        risk_score -= 10
    
    if risk_score < 0:
        risk_score = 0
    if risk_score > 100:
        risk_score = 100

    # Determine verdict based on combined analysis
    if ai_verdict == "PHISHING" and ai_confidence >= 60:
        verdict = "CRITICAL PHISHING"
    elif risk_score >= 70:
        verdict = "CRITICAL PHISHING"
    elif ai_verdict == "PHISHING" or risk_score >= 45:
        verdict = "SUSPICIOUS"
    elif ai_verdict == "SUSPICIOUS" or risk_score >= 30:
        verdict = "SUSPICIOUS"
    elif zero_day_risk:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- FINAL VERDICT ---{Style.RESET_ALL}")
    if verdict == "CRITICAL PHISHING":
        print(f"{Fore.RED}{Style.BRIGHT}[!!!] {verdict}{Style.RESET_ALL}")
    elif verdict == "SUSPICIOUS":
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] {verdict} (Risk indicators found){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}{Style.BRIGHT}[+] {verdict}{Style.RESET_ALL}")

    print(f"{Fore.BLUE}{Style.BRIGHT}========================================={Style.RESET_ALL}\n")
    
    # Offline dataset intel summary
    k_status, k_msg = query_kaggle_online_intel(clean_url, offline_data)

    report = {
        "target": clean_url,
        "verdict": verdict,
        "risk_score": risk_score,
        "kaggle": {"status": k_status, "detail": k_msg},
        "offline_datasets": offline_data,
        "domain": d_info,
        "virustotal": {"status": v_status, "message": v_msg},
        "abuseipdb": abuse_data,
        "urlscan": urlscan_data,
        "ai_analysis": {
            "verdict": ai_verdict,
            "confidence": ai_confidence,
            "flags": ai_flags
        },
        "ai_report": final_analysis,
        "final_reasoning": final_analysis,
        "recommendation": (
            "IMMEDIATE ACTION: Block URL and investigate sender." if verdict == "CRITICAL PHISHING"
            else "CAUTION: Review and verify sender identity before interacting." if verdict == "SUSPICIOUS"
            else "No immediate threats detected, but exercise caution with unfamiliar links."
        )
    }

    return report


def scan_url_master(url):
    return asyncio.run(async_scan_url_master(url))



def bulk_scan(file_path):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] File not found!{Style.RESET_ALL}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    print(f"\n{Fore.YELLOW}[*] Processing {len(lines)} lines from file...{Style.RESET_ALL}")
    for line in lines:
        raw = line.strip()
        if not raw:
            continue

        match = URL_PATTERN.search(raw)
        if match:
            scan_url_master(match.group(1))
        else:
            print(f"{Fore.YELLOW}[!] Skipped non-URL line: {raw}{Style.RESET_ALL}")
