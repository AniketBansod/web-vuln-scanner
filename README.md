<div align="center">

# Web Vulnerability Scanner

Fast, lightweight Python/Flask scanner that crawls a target, probes for reflected XSS and basic SQL injection, checks missing security headers, and produces JSON + rich HTML reports.

<br/>

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2%2B-000?logo=flask)](https://flask.palletsprojects.com/)
[![Requests](https://img.shields.io/badge/HTTP-requests-6DB33F)](https://requests.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#-license)

</div>

## 🚀 Features

- Reflected XSS detection for GET parameters and HTML forms (GET/POST)
- Basic and error‑based SQLi detection via payloads and signature matching
- Missing security header checks: CSP, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy, Permissions‑Policy, and HSTS (HTTPS)
- Same‑origin BFS crawler with auto depth and page cap
- Form discovery and testing with payload injection
- Parallel requests using `ThreadPoolExecutor` and Requests connection pooling
- JSON report generation plus a filterable HTML report UI
- Flask web UI to start scans and view/download reports
- Minimal REST endpoint to poll scan status

## 🧠 Architecture

**Technologies**: Python, Flask, Requests, BeautifulSoup.

- The Flask UI queues a background thread per scan and exposes pages for task status and report viewing/downloading.
- The scanner core crawls same‑origin pages, tests forms and GET params with SQLi/XSS payloads, and performs baseline header analysis.
- Results are aggregated and written to `report.json`; the HTML report view enriches and summarizes findings.

```
┌──────────┐      HTTP       ┌─────────────┐        orchestrates        ┌───────────────────────────────┐
│ Browser  │ ─────────────▶ │ Flask UI    │ ─────────────────────────▶ │ Scanner Core (crawler, tests) │
└──────────┘                │ webapp/app  │                             │  injector/analyzer/requester  │
                            └─────┬───────┘                             └───────────────┬───────────────┘
                                  │ JSON file                                         HTTP to target
                                  ▼
                           ┌─────────────┐
                           │ report.json │ ──▶ HTML report view (templates/report.html)
                           └─────────────┘
```

## 🛠️ Tech Stack

- Python 3.x
- Flask (web UI)
- Requests (HTTP client with retry/connection pooling)
- BeautifulSoup4 (HTML parsing)
- Standard library: `concurrent.futures`, `urllib.parse`, `threading`, `json`

## 📦 Installation

> Windows PowerShell commands shown; adapt for your OS if needed.

1. Clone and enter the project

```powershell
git clone https://github.com/AniketBansod/web-vuln-scanner.git
cd web-vuln-scanner\vuln_scanner
```

2. Create a virtual environment and install dependencies

```powershell
python -m venv .venv
\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3. (Optional) PowerShell policy if activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
\.venv\Scripts\Activate.ps1
```

## 🧪 Running the Project

### Development (Flask UI)

```powershell
python .\webapp\app.py
```

Open http://127.0.0.1:5001 and submit a target URL you are authorized to test.

### CLI Scanner

```powershell
# From the vuln_scanner directory
python -m scanner.main "http://example.test/path?param=value" 2 50
```

Arguments:

- `target_url` (required) – starting URL
- `depth` (optional, default auto=2) – crawl depth (0 = only the given page)
- `max_pages` (optional, default=50) – page crawl cap

### Production

- Disable debug and run behind a production WSGI server or reverse proxy of your choice. A Dockerfile or Procfile is not included in this repository.

## 🔍 Usage

- Start a scan from the UI’s home page by entering a URL.
- You’ll be redirected to a task page that polls status; when complete, open the HTML report or download the JSON.

Example JSON report (trimmed):

```json
{
  "target": "http://example.test",
  "timestamp": "2025-01-01 12:00:00",
  "findings": [
    {
      "type": "XSS-reflected",
      "param": "q",
      "payload": "<script>alert(1)</script>",
      "url": "http://example.test/?q=%3Cscript%3Ealert(1)%3C/script%3E",
      "evidence": "payload reflected in response body"
    }
  ]
}
```

## ⚙️ Configuration

- No required environment variables for local development.
- Defaults you can tune in code:
  - Crawl depth (UI): `depth = 2` in `webapp/app.py` (POST handler on `/`).
  - Concurrency and limits: see `scan_target` in `scanner/main.py` (`workers`, `max_pages`).
  - Port: `webapp/app.py` runs on `5001`.
  - Secret key: `app.secret_key` is set in `webapp/app.py`; change before deploying.

## 🧵 API Endpoints

- `GET /` – Home page; form to start a scan.
- `POST /` – Submit `target_url`; enqueues a background scan and redirects to task page.
- `GET /task/<task_id>` – Task status page.
- `GET /task/<task_id>/status.json` – JSON status for polling:
  - `{ status: queued|running|done|error, target, reportView, reportDownload }`
- `GET /report/<task_id>/view` – HTML report view.
- `GET /report/<task_id>/download` – Download the JSON report.

## 📈 Performance / Benchmarks

- Parallel per‑page scanning via `ThreadPoolExecutor`.
- Requests session with retry and pooled connections for better throughput.
- Simple heuristics (e.g., response length change) to flag suspected SQLi when no explicit error signature is found.

## 🧩 Folder Structure

```
vuln_scanner/
  scanner/            # Core scanning library
    main.py           # Orchestrates crawl → scan → report (CLI entry)
    crawler.py        # Same‑origin BFS crawler
    form_tester.py    # Parse and test forms (GET/POST)
    injector.py       # Generate parameterized test cases
    analyzer.py       # Header checks, SQL error & XSS reflection helpers
    requester.py      # Session with retries + connection pooling
    signatures.py     # Payloads and regex signatures
    reporter.py       # JSON report writer + console pretty‑print
  webapp/             # Flask UI
    app.py            # Routes, background task, recent reports, status JSON
    templates/        # index.html, task.html, report.html
    static/           # style.css
    reports/          # Saved JSON reports
  requirements.txt
  README.md
```

## 🛡️ Security

- Use only on systems you own or are explicitly authorized to test.
- Same‑origin scoping in the crawler limits traversal to the target host.
- Heuristic detection only; results can contain false positives/negatives.
- Not implemented: JWT/OAuth flows, rate limiting, role‑based access, CSRF‑aware sequences.

## 📦 Deployment

- Local development: run the Flask app directly (`python webapp/app.py`).
- Production: run the Flask app behind a production‑grade WSGI server and reverse proxy; configure the secret key and HTTPS at the proxy/load balancer. CI/CD and Docker files are not included in this repository.

## 🧠 Future Improvements

- DOM‑based XSS and client‑side sink detection
- Time‑based/blind SQLi strategies and more DB error signatures
- Auth/session handling and scripted form/login flows
- Smarter crawl (robots.txt, sitemap.xml, rate control, exclusions)
- Enhanced report UI: per‑page grouping, diffing across runs, export formats
- Configurable payload sets and per‑host tuning
- Proxy support and request throttling
- Headless browser integration for JS‑heavy apps
- Optional `.env` based configuration and logging levels

## 📝 License

MIT. See the LICENSE file (add one if missing) for details.

## 🙌 Acknowledgements

- Built with Flask, Requests, and BeautifulSoup.
- Informed by common OWASP testing techniques and public test targets.
