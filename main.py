import subprocess
import requests
import urllib3
import argparse
import os
import shutil
import json
import random
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings()
init(autoreset=True)

# =====================================================
# BANNER
# =====================================================

BANNER = f"""
{Fore.CYAN}
========================================================
               CRLF Recon Pipeline
========================================================
{Style.RESET_ALL}
"""

print(BANNER)

# =====================================================
# ARGPARSE
# =====================================================

parser = argparse.ArgumentParser(
    description="CRLF/Header Injection Recon Pipeline"
)

parser.add_argument(
    "-l",
    "--list",
    required=True,
    help="Arquivo contendo hosts/subdomínios"
)

parser.add_argument(
    "-p",
    "--payloads",
    default="payloads.txt",
    help="Arquivo de payloads"
)

parser.add_argument(
    "-o",
    "--output",
    default="output",
    help="Diretório de saída"
)

parser.add_argument(
    "-t",
    "--threads",
    type=int,
    default=30,
    help="Número de threads"
)

parser.add_argument(
    "--timeout",
    type=int,
    default=10,
    help="Timeout HTTP"
)

parser.add_argument(
    "--rate",
    type=float,
    default=0.1,
    help="Delay entre requests"
)

parser.add_argument(
    "--proxy",
    help="Proxy HTTP"
)

args = parser.parse_args()

# =====================================================
# CONFIG
# =====================================================

SUBDOMAIN_FILE = args.list
PAYLOAD_FILE = args.payloads
OUTPUT_DIR = args.output
THREADS = args.threads
TIMEOUT = args.timeout
RATE_LIMIT = args.rate
PROXY = args.proxy

LIVE_HOSTS_FILE = os.path.join(
    OUTPUT_DIR,
    "live_hosts.txt"
)

RESULTS_JSON = os.path.join(
    OUTPUT_DIR,
    "results.json"
)

FINDINGS_FILE = os.path.join(
    OUTPUT_DIR,
    "findings.txt"
)

REPORT_FILE = os.path.join(
    OUTPUT_DIR,
    "report.md"
)

# =====================================================
# VALIDATIONS
# =====================================================

if not os.path.isfile(SUBDOMAIN_FILE):

    print(f"{Fore.RED}[-] Lista de hosts não encontrada")
    exit(1)

if not os.path.isfile(PAYLOAD_FILE):

    print(f"{Fore.RED}[-] Arquivo de payloads não encontrado")
    exit(1)

HTTPX_PATH = shutil.which("httpx")

if not HTTPX_PATH:

    print(f"{Fore.RED}[-] httpx não encontrado no PATH")
    exit(1)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =====================================================
# LOAD PAYLOADS
# =====================================================

with open(PAYLOAD_FILE, "r") as f:

    PAYLOADS = [
        line.strip()
        for line in f
        if line.strip()
    ]

# =====================================================
# USER AGENTS
# =====================================================

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/537.36",
    "Edge/120.0"
]

# =====================================================
# REQUEST SESSION
# =====================================================

session = requests.Session()

retry = Retry(
    total=2,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504]
)

adapter = HTTPAdapter(max_retries=retry)

session.mount("http://", adapter)
session.mount("https://", adapter)

if PROXY:

    session.proxies = {
        "http": PROXY,
        "https": PROXY
    }

# =====================================================
# DISCOVER LIVE HOSTS
# =====================================================

print(f"{Fore.YELLOW}[+] Descobrindo hosts ativos...")

command = [
    HTTPX_PATH,
    "-silent",
    "-l",
    SUBDOMAIN_FILE
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

live_hosts = [
    h.strip()
    for h in result.stdout.splitlines()
    if h.strip()
]

with open(LIVE_HOSTS_FILE, "w") as f:

    for host in live_hosts:
        f.write(host + "\n")

print(
    f"{Fore.GREEN}[+] Hosts ativos encontrados: {len(live_hosts)}"
)

# =====================================================
# FINGERPRINTS
# =====================================================

def fingerprint_waf(headers):

    signatures = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "imperva": "Imperva",
        "sucuri": "Sucuri",
        "fastly": "Fastly"
    }

    header_string = str(headers).lower()

    for sig, name in signatures.items():

        if sig in header_string:
            return name

    return None

# =====================================================
# ANALYSIS
# =====================================================

findings = []

def analyze_headers(headers):

    indicators = []

    suspicious = [
        "Transfer-Encoding",
        "X-Cache",
        "Via",
        "Server",
        "X-Powered-By"
    ]

    for h in suspicious:

        if h in headers:

            indicators.append({
                "header": h,
                "value": headers.get(h)
            })

    return indicators

def detect_smuggling_indicators(headers):

    indicators = []

    if "Transfer-Encoding" in headers:
        indicators.append("Transfer-Encoding presente")

    if "Content-Length" in headers:
        indicators.append("Content-Length presente")

    if (
        "Transfer-Encoding" in headers
        and "Content-Length" in headers
    ):
        indicators.append(
            "Possível TE.CL ambiguity"
        )

    return indicators

def severity_score(vulnerable, smuggling, waf):

    if vulnerable:
        return "HIGH"

    if smuggling:
        return "MEDIUM"

    if waf:
        return "LOW"

    return "INFO"

# =====================================================
# TEST FUNCTION
# =====================================================

def test_target(host, payload):

    target = f"{host}/{payload}"

    headers_to_test = {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": payload,
        "X-Forwarded-For": payload
    }

    try:

        response = session.get(
            target,
            headers=headers_to_test,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )

        response_headers = dict(response.headers)

        vulnerable = False

        header_string = str(response.headers)

        if (
            "X-Bugbounty-Test" in header_string
            or "crlf=injected" in header_string
            or "X-Test" in header_string
        ):

            vulnerable = True

        waf = fingerprint_waf(response_headers)

        header_indicators = analyze_headers(
            response_headers
        )

        smuggling_indicators = detect_smuggling_indicators(
            response_headers
        )

        severity = severity_score(
            vulnerable,
            smuggling_indicators,
            waf
        )

        result = {
            "target": target,
            "status_code": response.status_code,
            "server": response_headers.get("Server"),
            "powered_by": response_headers.get("X-Powered-By"),
            "content_type": response_headers.get("Content-Type"),
            "redirect": response_headers.get("Location"),
            "waf": waf,
            "possible_vulnerable": vulnerable,
            "severity": severity,
            "header_indicators": header_indicators,
            "smuggling_indicators": smuggling_indicators
        }

        print(f"{Fore.CYAN}[TARGET] {target}")
        print(f"  Status: {response.status_code}")
        print(f"  Severity: {severity}")

        if waf:
            print(f"  WAF/CDN: {waf}")

        if smuggling_indicators:

            print(
                f"{Fore.YELLOW}[!] Indicadores de Smuggling encontrados"
            )

        if vulnerable:

            print(
                f"{Fore.RED}[!!!] Possível Header Injection"
            )

            findings.append(target)

        print("-" * 60)

        time.sleep(RATE_LIMIT)

        return result

    except Exception as e:

        return {
            "target": target,
            "error": str(e),
            "severity": "ERROR"
        }

# =====================================================
# EXECUTION
# =====================================================

print(f"{Fore.YELLOW}[+] Iniciando pipeline...\n")

scan_results = []

with ThreadPoolExecutor(max_workers=THREADS) as executor:

    futures = []

    for host in live_hosts:

        for payload in PAYLOADS:

            futures.append(
                executor.submit(
                    test_target,
                    host,
                    payload
                )
            )

    for future in as_completed(futures):

        scan_results.append(
            future.result()
        )

# =====================================================
# SAVE RESULTS
# =====================================================

with open(RESULTS_JSON, "w") as jf:

    json.dump(
        scan_results,
        jf,
        indent=4
    )

with open(FINDINGS_FILE, "w") as f:

    for item in findings:
        f.write(item + "\n")

# =====================================================
# MARKDOWN REPORT
# =====================================================

with open(REPORT_FILE, "w") as md:

    md.write("# CRLF Recon Pipeline Report\n\n")

    md.write(
        f"Targets analisados: {len(scan_results)}\n\n"
    )

    for item in scan_results:

        md.write("## Target\n\n")

        md.write(
            f"- URL: {item.get('target')}\n"
        )

        md.write(
            f"- Status: {item.get('status_code')}\n"
        )

        md.write(
            f"- Severity: {item.get('severity')}\n"
        )

        md.write(
            f"- WAF/CDN: {item.get('waf')}\n"
        )

        md.write(
            f"- Server: {item.get('server')}\n"
        )

        md.write(
            f"- Vulnerável: {item.get('possible_vulnerable')}\n\n"
        )

# =====================================================
# FINAL
# =====================================================

print(f"\n{Fore.CYAN}[+] Scan finalizado")

print(
    f"{Fore.CYAN}[+] JSON salvo em: {RESULTS_JSON}"
)

print(
    f"{Fore.CYAN}[+] Markdown salvo em: {REPORT_FILE}"
)

print(
    f"{Fore.CYAN}[+] Findings salvos em: {FINDINGS_FILE}"
)

print(
    f"{Fore.GREEN}[+] Targets analisados: {len(scan_results)}"
)

if findings:

    print(
        f"{Fore.RED}[!!!] Possíveis vulnerabilidades: {len(findings)}"
    )

else:

    print(
        f"{Fore.GREEN}[+] Nenhuma reflexão detectada"
    )
