# CRLF Recon Pipeline

Ferramenta de Recon Ofensivo para detecção de:

- CRLF Injection
- Header Injection
- Passive Smuggling Indicators
- Header Anomalies
- WAF/CDN Fingerprinting

## Features

- Multi-threading
- JSON Output
- Markdown Reports
- Proxy Support
- Retry/Backoff
- Severity Scoring
- Header Analysis
- Smuggling Indicators
- WAF Fingerprinting

## Instalação

```bash
git clone https://github.com/SEU-USUARIO/crlf-recon-pipeline.git

cd crlf-recon-pipeline

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Dependências

- Python 3
- httpx (ProjectDiscovery)

Instalar:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Uso

```bash
python3 main.py -l subdomains.txt
```

Modo avançado:

```bash
python3 main.py -l subdomains.txt -t 100 --rate 0.05
```

Com proxy:

```bash
python3 main.py -l subdomains.txt --proxy http://127.0.0.1:8080
```

## Outputs

A ferramenta gera:

- results.json
- report.md
- findings.txt

## Aviso

Ferramenta destinada apenas para:
- Bug Bounty autorizado
- Pentest autorizado
- Ambientes de laboratório
