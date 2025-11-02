# Vuln Scanner — Minimal Web Vulnerability Scanner

## Overview

This project provides a simple vulnerability scanner that can:

- Test GET parameters for reflected XSS and basic SQL injection signatures
- Parse and test HTML forms (GET/POST) for the same issues
- Optionally crawl same-origin links from a starting URL to a configurable depth
- Produce a JSON report and a small web UI to run scans and view results

## Components

- `scanner/` — core scanning library
  - `main.py` — entry point (CLI) and orchestrator. Supports optional crawl depth.
  - `crawler.py` — simple same-origin BFS crawler
  - `form_tester.py` — parses forms and injects payloads
  - `injector.py` — generates parameterized test cases
  - `analyzer.py` — detection helpers (SQL error regex, reflection checks)
  - `requester.py` — HTTP session with retries
  - `signatures.py` — payloads and regexes
  - `reporter.py` — pretty print and JSON report writing
- `webapp/` — Flask web UI to submit a target URL, run scans in background, and view/download reports

## Install

Create a virtual environment (optional) and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## CLI Usage

Run a single-page scan:

```powershell
python -m scanner.main "http://example.com/page?param=1"
```

Enable crawling (depth 1, up to 50 pages):

```powershell
python -m scanner.main "http://example.com/" 1 50
```

## Web UI

Start the web app:

```powershell
python webapp/app.py
```

Open http://localhost:5001 and submit a URL. Optionally set Crawl depth to scan same-origin pages discovered from links.

## Notes & Ethics

- Only scan targets you own or have explicit permission to test.
- This is an educational tool with basic signatures and heuristics; it may produce false positives/negatives.
- DOM-based XSS, blind SQLi, and advanced checks are not fully implemented.

## Roadmap (Next Level)

- Robust site crawler (robots.txt, sitemaps, rate limiting, concurrency)
- DOM-based XSS with a headless browser
- Blind/boolean/time-based SQLi detection strategies
- Additional checks (open redirect, SSRF, LFI/RFI, command injection, directory traversal)
- Security headers and cookie analysis
- Rich reports with severity, CWE/OWASP mapping
