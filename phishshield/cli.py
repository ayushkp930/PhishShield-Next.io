import argparse, asyncio, json, sys
from pathlib import Path
from .analyzer import analyze_url, analyze_email_text
from .live_inspector import inspect_public_site, score_inspection_result, UnsafeTarget
from . import store, intel
from dotenv import load_dotenv

def _show(r):
    colors={'HIGH RISK':'\033[91m','SUSPICIOUS':'\033[93m','INCONCLUSIVE':'\033[96m'}; reset='\033[0m'
    print(f"\nPhishShield Next | {r['verdict']} | Risk {r['risk_score']}/100")
    print(f"Target: {r.get('normalized_url',r.get('input','email analysis'))}")
    for x in r.get('signals',[]): print(f"  [{x['severity'].upper():8}] {x['title']}: {x['detail']}")
    for x in r.get('flags',[]): print(f"  [REVIEW] {x}")
    inspection = r.get('inspection') or {}
    for page in inspection.get('pages', []):
        print(f"\nPAGE: HTTP {page.get('status', '—')} | {page.get('url', '')}")
        if page.get('title'): print(f"  Title: {page['title']}")
        for finding in page.get('findings', []): print(f"  [PAGE] {finding}")
        for action in page.get('external_form_action_urls', []): print(f"  [FORM DESTINATION] {action}")
    for error in inspection.get('errors', []): print(f"  [FETCH NOTE] {error}")
    print("\nRecommendation:",r.get('recommendation',r.get('note','')))
    if 'limitations' in r:
        print("\nLimitations:")
        for x in r['limitations']: print(" -",x)
def main():
    parser=argparse.ArgumentParser(prog='phishshield',description='PhishShield Next — defensive phishing triage')
    sub=parser.add_subparsers(dest='command',required=True)
    scan=sub.add_parser('scan',help='Analyze a URL/domain without fetching it'); scan.add_argument('target'); scan.add_argument('--json',action='store_true'); scan.add_argument('--no-history',action='store_true')
    email=sub.add_parser('email',help='Analyze a saved email text/EML file locally'); email.add_argument('path'); email.add_argument('--json',action='store_true')
    inspect=sub.add_parser('inspect',help='Fetch and inspect a bounded set of public web pages'); inspect.add_argument('target'); inspect.add_argument('--pages',type=int,choices=range(1,11),default=3); inspect.add_argument('--json',action='store_true'); inspect.add_argument('--no-history',action='store_true')
    reputation=sub.add_parser('reputation',help='Query configured threat-intelligence providers and WHOIS/RDAP (shares indicator externally)'); reputation.add_argument('target'); reputation.add_argument('--json',action='store_true')
    whois=sub.add_parser('whois',help='Look up public domain/IP registration metadata via RDAP'); whois.add_argument('target'); whois.add_argument('--json',action='store_true')
    web=sub.add_parser('web',help='Start the web dashboard'); web.add_argument('--host',default=None); web.add_argument('--port',type=int,default=None)
    args=parser.parse_args()
    load_dotenv()
    if args.command=='web':
        import os, uvicorn
        uvicorn.run('phishshield.web:app',host=args.host or os.getenv('PHISHSHIELD_HOST','127.0.0.1'),port=args.port or int(os.getenv('PHISHSHIELD_PORT','8000')),reload=False); return
    try:
        if args.command=='scan':
            result=analyze_url(args.target)
            if not args.no_history: store.save(result)
        elif args.command=='email':
            text=Path(args.path).read_text(encoding='utf-8',errors='replace'); result=analyze_email_text(text)
        elif args.command=='reputation':
            result=asyncio.run(intel.lookup_reputation(args.target))
        elif args.command=='whois':
            result=asyncio.run(intel.lookup_whois_rdap(args.target))
        else:
            result=score_inspection_result(asyncio.run(inspect_public_site(args.target,args.pages)))
            if not args.no_history: store.save(result)
        if args.json: print(json.dumps(result,indent=2))
        elif args.command in {'reputation','whois'}: print(json.dumps(result,indent=2,ensure_ascii=False))
        else: _show(result)
    except (ValueError,OSError,UnsafeTarget) as e:
        print(f'Error: {e}',file=sys.stderr); return 2
    return 0
if __name__=='__main__': raise SystemExit(main())
