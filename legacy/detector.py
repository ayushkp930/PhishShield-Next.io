import os
import url_scanner
import email_analyzer
import ai_analyzer
from colorama import Fore, Style, init
from dotenv import load_dotenv

init(autoreset=True)
load_dotenv()


def _status_dot(is_ready):
    return f"{Fore.GREEN}● READY{Style.RESET_ALL}" if is_ready else f"{Fore.YELLOW}● MISSING{Style.RESET_ALL}"


def show_startup_health():
    groq_key = os.getenv("GROQ_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    urlscan_key = os.getenv("URLSCAN_API_KEY")

    offline = url_scanner.get_offline_cache_stats(preload=True)

    print(f"\n{Fore.BLUE}{Style.BRIGHT}====================================================")
    print("             PHISHSHIELD PRO STARTUP HEALTH")
    print(f"===================================================={Style.RESET_ALL}")
    print(f"  {Fore.CYAN}AI Models:{Style.RESET_ALL}")
    print(f"    Groq Model:   {Fore.WHITE}{url_scanner.GROQ_MODEL}{Style.RESET_ALL}")
    print(f"    Gemini Model: {Fore.WHITE}{url_scanner.GEMINI_MODEL}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}API Keys:{Style.RESET_ALL}")
    print(f"    Groq:        {_status_dot(bool(groq_key))}")
    print(f"    Gemini:      {_status_dot(bool(gemini_key))}")
    print(f"    VirusTotal:  {_status_dot(bool(vt_key))}")
    print(f"    AbuseIPDB:   {_status_dot(bool(abuse_key))}")
    print(f"    URLScan:     {_status_dot(bool(urlscan_key))}")
    print(f"  {Fore.CYAN}Offline Datasets:{Style.RESET_ALL}")
    print(
        f"    Loaded: {Fore.WHITE}{offline.get('sources_loaded', 0)} file(s){Style.RESET_ALL} | "
        f"Malicious URLs: {Fore.WHITE}{offline.get('known_malicious_urls', 0)}{Style.RESET_ALL} | "
        f"Domains: {Fore.WHITE}{offline.get('known_malicious_domains', 0)}{Style.RESET_ALL}"
    )

def check_api_status():
    """Check and display current API key status"""
    groq_key = os.getenv("GROQ_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- API STATUS ---{Style.RESET_ALL}")
    print(f"  {Fore.GREEN if groq_key else Fore.YELLOW}● Groq API: {'Loaded' if groq_key else 'Not loaded'}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN if gemini_key else Fore.YELLOW}● Gemini API: {'Loaded' if gemini_key else 'Not loaded'}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN if vt_key else Fore.YELLOW}● VirusTotal API: {'Loaded' if vt_key else 'Not loaded'}{Style.RESET_ALL}")


def add_custom_api():
    """Allow user to add or override API keys"""
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}==================================================")
    print("              ADD YOUR OWN API KEYS")
    print(f"=================================================={Style.RESET_ALL}")
    
    check_api_status()
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- Enter API Keys (leave blank to skip) ---{Style.RESET_ALL}")
    
    # Groq API
    groq_input = input(f"{Fore.WHITE}Enter Groq API Key (or press Enter to skip): {Style.RESET_ALL}").strip()
    if groq_input:
        os.environ["GROQ_API_KEY"] = groq_input
        print(f"{Fore.GREEN}[+] Groq API key updated.{Style.RESET_ALL}")
    
    # Gemini API
    gemini_input = input(f"{Fore.WHITE}Enter Gemini API Key (or press Enter to skip): {Style.RESET_ALL}").strip()
    if gemini_input:
        os.environ["GEMINI_API_KEY"] = gemini_input
        print(f"{Fore.GREEN}[+] Gemini API key updated.{Style.RESET_ALL}")
    
    # VirusTotal API
    vt_input = input(f"{Fore.WHITE}Enter VirusTotal API Key (or press Enter to skip): {Style.RESET_ALL}").strip()
    if vt_input:
        os.environ["VIRUSTOTAL_API_KEY"] = vt_input
        print(f"{Fore.GREEN}[+] VirusTotal API key updated.{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] API keys configured!{Style.RESET_ALL}")
    check_api_status()
    input(f"{Fore.CYAN}[?] Press Enter to return to main menu...{Style.RESET_ALL}")


def main_menu():
    while True:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}==============================================")
        print("      PHISHSHIELD PRO | PROFESSIONAL THREAT SUITE")
        print(f"=============================================={Style.RESET_ALL}")
        print(f"{Fore.CYAN}[1] 🔎 Start Threat Assessment")
        print(f"{Fore.YELLOW}[2] 🔑 Add Your Own API Keys")
        print(f"{Fore.RED}[3] ❌ Exit")

        choice = input(f"\n{Fore.GREEN}{Style.BRIGHT}[?] Choice: {Style.RESET_ALL}")

        if choice == '1':
            target = input(f"{Fore.WHITE}Enter URL or email file path: {Style.RESET_ALL}").strip()
            if os.path.exists(target):
                email_analyzer.analyze_email_file(target)
                print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Email analysis complete.{Style.RESET_ALL}")
            else:
                report = url_scanner.scan_url_master(target)
                if report:
                    url_scanner.display_report_menu(report)
        elif choice == '2':
            add_custom_api()
        elif choice == '3':
            print(f"{Fore.YELLOW}Goodbye. Stay secure.{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Try again.{Style.RESET_ALL}")


if __name__ == "__main__":
    show_startup_health()
    main_menu()
