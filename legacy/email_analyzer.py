import email
from email import policy
import re
from colorama import Fore, Style, init
import ai_analyzer
import url_scanner

init(autoreset=True)
HTTP_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+")
# Domain pattern - only actual domains, no email addresses
DOMAIN_URL_PATTERN = re.compile(r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>'\"]*)?)")
# Email pattern to filter out
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def _extract_urls_from_headers(msg):
    """Extract URLs/domains from email headers (From, Reply-To, Return-Path, Received)"""
    urls = []
    header_fields = ['From', 'Reply-To', 'Return-Path', 'Received', 'Sender']
    
    for field in header_fields:
        header_value = msg.get(field, '')
        if header_value:
            # Extract HTTP URLs
            urls += HTTP_URL_PATTERN.findall(str(header_value))
            # Extract domains
            urls += [match for match in DOMAIN_URL_PATTERN.findall(str(header_value)) 
                    if match not in urls and len(match) > 3]
    
    # Filter out email addresses and duplicates
    urls = [url for url in urls if not EMAIL_PATTERN.fullmatch(url)]
    return list(set(urls))


def _strip_html(text):
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.S | re.I)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.S | re.I)
    return re.sub(r'<[^>]+>', '', text)


def _get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                return part.get_payload(decode=True).decode(errors='ignore')
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html = part.get_payload(decode=True).decode(errors='ignore')
                return _strip_html(html)
        return ''

    payload = msg.get_payload(decode=True)
    if payload is None:
        return ''
    text = payload.decode(errors='ignore')
    if msg.get_content_type() == 'text/html':
        return _strip_html(text)
    return text


def analyze_email_file(file_path):
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}==================================================")
    print("       [EMAIL] PHISHSHIELD PRO EMAIL ANALYZER [EMAIL]")
    print(f"=================================================={Style.RESET_ALL}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_text = f.read()

        msg = email.message_from_string(raw_text, policy=policy.default)

        print(f"\n{Fore.CYAN}{Style.BRIGHT}--- HEADER INFORMATION ---{Style.RESET_ALL}")
        subject = str(msg.get('Subject', 'N/A'))
        from_addr = str(msg.get('From', 'N/A'))
        print(f"  {Fore.WHITE}• From:    {from_addr}")
        print(f"  {Fore.WHITE}• Subject: {subject}")

        body = _get_email_body(msg)
        
        # Extract URLs from entire raw email text (most comprehensive)
        urls = HTTP_URL_PATTERN.findall(raw_text)
        urls += [match for match in DOMAIN_URL_PATTERN.findall(raw_text) if match not in urls and len(match) > 3]
        # Filter out email addresses
        urls = [url for url in urls if not EMAIL_PATTERN.fullmatch(url)]
        # Remove duplicates and sort
        urls = list(set(urls))
        urls.sort()
        
        if not urls:
            print(f"\n{Fore.YELLOW}[!] No domains found in email text. Using AI extraction...{Style.RESET_ALL}")
            urls = _extract_urls_with_ai(raw_text)
            if not urls:
                print(f"{Fore.YELLOW}[!] AI extraction also failed.{Style.RESET_ALL}")

        if urls:
            urls = list(set(urls))  # Remove duplicates
            urls.sort()  # Sort for consistent display
            
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] Found {len(urls)} URL(s)/Domain(s) in Email Content:{Style.RESET_ALL}")
            for i, url in enumerate(urls, 1):
                print(f"  [{i}] {url}")
            
            # Ask user if they want to scan these URLs
            scan_choice = input(f"\n{Fore.CYAN}[?] Scan all URLs? (yes/no): {Style.RESET_ALL}").strip().lower()
            
            if scan_choice in ['yes', 'y', '1']:
                urls_to_scan = urls
            elif scan_choice in ['no', 'n', '0']:
                # Ask user to select specific URLs
                print(f"{Fore.CYAN}[?] Enter URL numbers to scan (comma-separated, e.g., 1,3,4):{Style.RESET_ALL}")
                selection = input(f"{Fore.GREEN}[?] Numbers: {Style.RESET_ALL}").strip()
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    urls_to_scan = [urls[i] for i in indices if 0 <= i < len(urls)]
                except Exception:
                    print(f"{Fore.YELLOW}[!] Invalid selection. Scanning all URLs instead.{Style.RESET_ALL}")
                    urls_to_scan = urls
            else:
                urls_to_scan = urls
            
            # Scan selected URLs
            for idx, url in enumerate(urls_to_scan, 1):
                url = url.strip()
                if url and len(url) > 3:
                    print(f"\n{Fore.MAGENTA}{'='*70}")
                    print(f"URL {idx}/{len(urls_to_scan)}: {url}")
                    print(f"{'='*70}{Style.RESET_ALL}")
                    
                    report = url_scanner.scan_url_master(url)
                    if report:
                        go_main_menu = url_scanner.display_report_menu(report)
                        if go_main_menu:
                            return
                    
                    # Ask before next URL if more than one
                    if idx < len(urls_to_scan):
                        next_choice = input(f"\n{Fore.CYAN}[?] Scan next URL? (yes/no): {Style.RESET_ALL}").strip().lower()
                        if next_choice not in ['yes', 'y', '1']:
                            print(f"{Fore.YELLOW}[!] Stopped scanning remaining URLs.{Style.RESET_ALL}")
                            break
        else:
            print(f"\n{Fore.GREEN}[+] No URLs found in the email file.{Style.RESET_ALL}")

        # Automatically run AI deep analysis on entire email
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.CYAN}[*] Running AI deep analysis on entire email...{Style.RESET_ALL}")
        ai_analyzer.analyze_with_ai(file_path)

    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error processing email: {e}{Style.RESET_ALL}")


def _extract_urls_with_ai(email_text):
    """Use AI to extract URLs/domains from email text when regex fails"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    if not GROQ_API_KEY and not GEMINI_API_KEY:
        return []
    
    extraction_prompt = f"""Extract all URLs, domains, and email addresses from this text. Return ONLY a comma-separated list with no explanations.

TEXT:
{email_text[:2000]}

URLS/DOMAINS/EMAILS (comma-separated):"""

    urls = []
    
    # Try Groq first
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": extraction_prompt}],
                model="llama3-8b-8192",
                temperature=0,
            )
            result = response.choices[0].message.content.strip()
            urls = [u.strip() for u in result.split(',') if u.strip() and len(u.strip()) > 3]
            return urls
        except:
            pass
    
    # Fallback to Gemini
    if GEMINI_API_KEY:
        try:
            from google import genai
            client = genai.Client(api_key=GEMINI_API_KEY)
            response = client.models.generate_content(
                model="gemini-1.5-flash",
                contents=extraction_prompt
            )
            result = response.text.strip()
            urls = [u.strip() for u in result.split(',') if u.strip() and len(u.strip()) > 3]
            return urls
        except:
            pass
    
    return urls

