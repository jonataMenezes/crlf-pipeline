# CRLF Recon Pipeline

███████╗██████╗ ██╗     ██╗      ██████╗ ██████╗ ██╗███╗   ██╗███████╗
██╔════╝██╔══██╗██║     ██║     ██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝
█████╗  ██████╔╝██║     ██║     ██║   ██║██████╔╝██║██╔██╗ ██║█████╗  
██╔══╝  ██╔═══╝ ██║     ██║     ██║   ██║██╔═══╝ ██║██║╚██╗██║██╔══╝  
███████╗██║     ███████╗███████╗╚██████╔╝██║     ██║██║ ╚████║███████╗
╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝



![Python](https://img.shields.io/badge/python-3.x-blue)
![GitHub release](https://img.shields.io/github/v/release/jonataMenezes/crlf-pipeline)
![License](https://img.shields.io/badge/license-MIT-green)


CRLF Recon Pipeline is a professional reconnaissance tool for detecting:

- CRLF Injection
- Header Injection
- Passive Smuggling Indicators
- Header Anomalies
- WAF/CDN Fingerprinting

## Features

- Multi-threaded scanning
- JSON output for automation
- Markdown reports
- Proxy support (Burp/ZAP)
- Retry/backoff with rate limiting
- Severity scoring for findings
- Header analysis and fingerprinting
- Redirect and anomaly detection
- Passive smuggling indicators

## Installation

Clone the repository:

```bash
git clone https://github.com/SEU-USUARIO/crlf-pipeline.git
cd crlf-pipeline
````

Create Python virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Install `httpx` (ProjectDiscovery):

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure `~/go/bin` is in your PATH.

## Usage

Basic scan:

```bash
python3 main.py -l subdomains.txt
```

Advanced scan with threads, timeout, and rate limit:

```bash
python3 main.py -l subdomains.txt -t 50 --timeout 15 --rate 0.1
```

Scan through Burp/ZAP proxy:

```bash
python3 main.py -l subdomains.txt --proxy http://127.0.0.1:8080
```

## Outputs

The tool generates:

* `results.json` → structured results for automation
* `report.md` → human-readable markdown report
* `findings.txt` → prioritized list of potential vulnerabilities

## Ethical Notice

This tool is intended **only for authorized testing** in:

* Bug Bounty programs
* Penetration testing with permission
* Laboratory environments

Unauthorized use against targets you do not own or have permission to test is illegal.

