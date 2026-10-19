import asyncio
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init
from urllib.parse import urlparse
from modules.threat_intel import ThreatIntel
from modules.offline_engine import OfflineEngine
from ai_analyzer import AIAnalyzer

# Initialize Colorama
init(autoreset=True)

class PhishShieldPro:
    def __init__(self):
        load_dotenv()
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        
        self.intel = ThreatIntel(self.vt_key, self.abuse_key)
        self.offline = OfflineEngine("phishing_site_urls.csv", "dataset_with_all_features v2.csv")
        self.ai = AIAnalyzer()

    async def scan_url(self, url: str):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] Initiating Multi-Layer Scan: {url}{Style.RESET_ALL}")
        domain = urlparse(url).netloc
        
        # 1. Offline Check (Instant)
        offline_res = self.offline.scan_url(url)
        
        # 2. Concurrent Online & AI Intel
        print(f"{Fore.YELLOW}[*] Querying Threat Intel & Dual-LLM Oracles...{Style.RESET_ALL}")
        
        # Gathering all data concurrently
        intel_task = self.intel.gather_intel(url, domain)
        ai_task = self.ai.get_dual_analysis(url)
        
        intel_res, ai_res = await asyncio.gather(intel_task, ai_task)
        
        self.display_report(url, offline_res, intel_res, ai_res)

    def display_report(self, url, offline, intel, ai_results):
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}{Style.BRIGHT}PHISHSHIELD PRO - FORENSIC REPORT")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # VT Results
        vt = intel['vt']
        vt_color = Fore.RED if vt.get('status') == 'malicious' else Fore.YELLOW if vt.get('status') == 'unknown' else Fore.GREEN
        print(f"{Fore.WHITE}VirusTotal: {vt_color}{vt.get('status').upper()} (Score: {vt.get('score', 'N/A')})")
        
        # RDAP / Zero-Day Logic
        rdap = intel['rdap']
        rdap_color = Fore.RED if rdap.get('status') == 'suspicious' else Fore.GREEN
        print(f"{Fore.WHITE}RDAP/WHOIS: {rdap_color}{rdap.get('status').upper()} - {rdap.get('reason', 'Domain lookup OK')}")
        
        # Offline Match
        if offline['match']:
            print(f"{Fore.RED}[!] BLACKLIST MATCH: {offline['source']} labeled this URL as {offline['label']}")

        # AI Analysis
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- AI ORACLE VERDICTS ---{Style.RESET_ALL}")
        for idx, res in enumerate(ai_results):
            source = "Gemini 1.5 Pro" if idx == 0 else "Llama-3 (Groq)"
            print(f"{Fore.CYAN}[{source}]{Style.RESET_ALL}\n{res}\n")

    async def run(self):
        print(f"{Fore.CYAN}{Style.BRIGHT}PhishShield Pro CLI v1.0{Style.RESET_ALL}")
        while True:
            target = input(f"\n{Fore.WHITE}Enter URL to scan (or 'exit' to quit): {Style.RESET_ALL}").strip()
            if target.lower() == 'exit':
                break
            if target:
                await self.scan_url(target)

if __name__ == "__main__":
    app = PhishShieldPro()
    asyncio.run(app.run())
