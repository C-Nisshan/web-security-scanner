# Aegis Security — Automated Web Application Security Scanner

A Python-based tool that automatically crawls a web application, discovers input points,
tests for common vulnerabilities (SQLi and XSS), and produces a professional HTML/PDF
report with severity ratings and remediation guidance.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [API Reference](#api-reference)
- [Module Documentation](#module-documentation)
- [Testing](#testing)
- [Ethics & Responsible Use](#ethics--responsible-use)
- [Roadmap](#roadmap)

---

## Features

| Module | Description |
|--------|-------------|
| **Surface Discovery** | Breadth-first crawler maps all reachable pages up to a configurable depth |
| **SQL Injection** | Error-based, boolean-based, and time-based detection |
| **XSS Detection** | Reflected XSS with context analysis (HTML body, attribute, script) |
| **Response Analysis** | Aggregates findings, assigns CVSS-inspired severity scores |
| **HTML Report** | Standalone, self-contained dark-themed report |
| **PDF Report** | Professional PDF via ReportLab with cover page, findings, and remediation |
| **REST API** | Flask backend with separate endpoints for each module |
| **Web UI** | Full assessment console with Discovery, Injection, and Full Scan tabs |

---

## Architecture

```
User (Browser) ──► Frontend (HTML/CSS/JS)
                        │
                        ▼ REST API calls
                   Flask app.py
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
      Crawler    PayloadEngine   ScannerController
                                      │
                          ┌───────────┼───────────┐
                          ▼           ▼           ▼
                    SQLiDetector  XSSDetector   (future)
                          │           │
                          └─────┬─────┘
                                ▼
                        ResponseAnalyzer
                                │
                                ▼
                        ReportGenerator
                         (HTML + PDF)
```

### High-Level Flow

```
User supplies URL
      │
      ▼
[Stage 1] Crawler enumerates pages (BFS)
      │
      ▼
[Stage 2] GET parameters extracted from each discovered URL
      │
      ▼
[Stage 3] SQLiDetector + XSSDetector inject payloads per param
      │
      ▼
[Stage 4] ResponseAnalyzer aggregates & ranks findings
      │
      ▼
[Stage 5] ReportGenerator produces HTML + PDF report
      │
      ▼
User downloads report
```

---

## Project Structure

```
aegis/
├── app.py                    # Flask REST API server
├── requirements.txt          # Python dependencies
├── README.md
│
├── scanner/
│   ├── __init__.py           # Package exports
│   ├── crawler.py            # BFS web crawler (Stage 1)
│   ├── payload_engine.py     # Raw payload injection (Stage 3 – simple)
│   ├── sqli_detector.py      # Advanced SQLi detection (Stage 3)
│   ├── xss_detector.py       # Advanced XSS detection (Stage 3)
│   ├── response_analyzer.py  # Finding aggregation & enrichment (Stage 4)
│   ├── report_generator.py   # HTML + PDF report generation (Stage 5)
│   └── controller.py         # Full pipeline orchestrator
│
├── reports/                  # Generated reports (auto-created)
│
└── frontend/
    ├── index.html
    ├── about.html
    ├── services.html
    ├── contact.html
    ├── scanner.html           # Main assessment console (updated)
    ├── css/
    │   ├── global.css
    │   ├── index.css
    │   ├── scanner.css
    │   ├── about.css
    │   ├── contact.css
    │   └── services.css
    └── js/
        ├── global.js
        ├── index.js
        ├── scanner.js         # Console controller (updated)
        ├── contact.js
        └── services.js
```

---

## Installation

### Prerequisites

- Python 3.10+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/your-username/aegis-security.git
cd aegis-security
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

**Optional — PDF report generation:**
```bash
pip install reportlab
```

---

## Running the Application

### Start the Flask backend

```bash
python app.py
```

The API server starts at `http://127.0.0.1:5000`.

### Open the frontend

Open `frontend/index.html` in your browser, or serve the folder with any static file server:

```bash
# Python one-liner
cd frontend
python -m http.server 8080
```

Then visit `http://localhost:8080`.

### Verify the backend is running

```bash
curl http://127.0.0.1:5000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "Aegis Security Platform",
  "modules": ["discovery", "injection", "analysis", "reporting"]
}
```

---

## API Reference

### `GET /api/health`
Health check.

---

### `POST /api/scan/crawl`
Surface discovery only.

**Request body:**
```json
{
  "target_url": "https://example.com",
  "max_depth":  2,
  "max_urls":   40
}
```

**Response:** `visited_urls`, `failed_urls`, `url_to_links`, crawl statistics.

---

### `POST /api/scan/payload`
Injection assessment against a single URL (uses `PayloadEngine`).

**Request body:**
```json
{
  "target_url":   "https://example.com/page?id=1",
  "payload_type": "both",
  "max_payloads": 20
}
```

**Response:** Per-payload results with `status`, `status_code`, `evidence`.

---

### `POST /api/scan/full`
**Full pipeline** — crawl → inject → analyse → report.

**Request body:**
```json
{
  "target_url":   "https://example.com",
  "max_depth":    2,
  "max_urls":     40,
  "max_targets":  10,
  "max_payloads": 20,
  "payload_type": "both"
}
```

**Response:**
```json
{
  "scan_id":    "a1b2c3d4",
  "analysis":   { "total_findings": 2, "overall_risk": "High", ... },
  "report_urls": {
    "html": "/api/report/a1b2c3d4/html",
    "pdf":  "/api/report/a1b2c3d4/pdf"
  }
}
```

---

### `GET /api/report/<scan_id>/html`
Download the standalone HTML report.

### `GET /api/report/<scan_id>/pdf`
Download the PDF report (requires `reportlab`).

### `GET /api/report/<scan_id>/summary`
JSON summary of a completed scan.

---

## Module Documentation

### `scanner/crawler.py` — `Crawler`
Breadth-first web crawler.

```python
from scanner import Crawler

crawler = Crawler(max_depth=2, max_urls=50)
result  = crawler.crawl("https://example.com")
print(result["visited_urls"])
```

| Parameter   | Default | Description                       |
|-------------|---------|-----------------------------------|
| `max_depth` | 3       | Maximum BFS depth from seed URL   |
| `max_urls`  | 100     | Hard cap on URLs visited          |
| `timeout`   | 8       | Per-request timeout (seconds)     |
| `delay`     | 0.3     | Polite pause between requests (s) |

---

### `scanner/sqli_detector.py` — `SQLiDetector`
Three-technique SQL injection detector.

```python
from scanner import SQLiDetector

det    = SQLiDetector()
result = det.detect("https://example.com/page?id=1", "id")
if result["confirmed"]:
    print(f"SQLi found! Severity: {result['highest_severity']}")
    print(f"Techniques: {result['technique_summary']}")
```

**Techniques:**
- **Error-based** — detects database error strings in responses
- **Boolean-based** — compares response sizes for true vs false conditions
- **Time-based** — measures actual delay from SLEEP/WAITFOR payloads

---

### `scanner/xss_detector.py` — `XSSDetector`
Context-aware XSS detection.

```python
from scanner import XSSDetector

det    = XSSDetector()
result = det.detect("https://example.com/search?q=test", "q")
if result["confirmed"]:
    print(f"XSS found! Executable payloads: {result['executable_count']}")
```

**Coverage:**
- HTML body injection (`<script>`, `<img>`, `<svg>`)
- Attribute break-out (`" onmouseover=...`)
- Script context (`'-alert(1)-'`)
- Encoding bypass variants

---

### `scanner/response_analyzer.py` — `ResponseAnalyzer`
Aggregates raw detector results into a ranked findings report.

```python
from scanner import SQLiDetector, XSSDetector, ResponseAnalyzer

# ... run detectors ...
analyzer = ResponseAnalyzer()
report   = analyzer.analyze(sqli_results, xss_results)
print(f"Overall risk: {report['overall_risk']}")
```

**Severity scale:**
| Level    | CVSS Range  | Description                          |
|----------|-------------|--------------------------------------|
| Critical | 9.0 – 10.0  | Boolean/time-based SQLi confirmed    |
| High     | 7.0 – 8.9   | Error-based SQLi / executable XSS   |
| Medium   | 4.0 – 6.9   | Reflected XSS (unconfirmed context) |
| Low      | 0.1 – 3.9   | Informational indicators             |

---

### `scanner/report_generator.py` — `ReportGenerator`
Generates HTML and PDF reports.

```python
from scanner import ReportGenerator

gen       = ReportGenerator(output_dir="reports")
html_path = gen.generate_html(analysis, scan_meta, "scan-001")
pdf_path  = gen.generate_pdf(analysis, scan_meta, "scan-001")
```

**HTML report** — fully self-contained, no external dependencies.  
**PDF report** — requires `reportlab` (`pip install reportlab`).

---

### `scanner/controller.py` — `ScannerController`
Runs the complete pipeline in one call.

```python
from scanner import ScannerController

controller = ScannerController(
    report_dir="reports",
    max_crawl_depth=2,
    max_crawl_urls=40,
    payload_type="both",
)
result = controller.run_scan("https://example.com")
print(result["analysis"]["overall_risk"])
print(result["report_html_path"])
```

---

## Testing

Test against intentionally vulnerable applications **only**. Recommended targets:

| Target             | Setup |
|--------------------|-------|
| [DVWA](https://github.com/digininja/DVWA) | `docker run -p 80:80 vulnerables/web-dvwa` |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `docker run -p 3000:3000 bkimminich/juice-shop` |
| [WebGoat](https://github.com/WebGoat/WebGoat) | `docker run -p 8080:8080 webgoat/goat-and-wolf` |

**Example test run against Juice Shop:**

```bash
# Start Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Run full scan via API
curl -X POST http://127.0.0.1:5000/api/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://localhost:3000","max_depth":2,"max_urls":30}'
```

---

## Ethics & Responsible Use

> **Only run scans against applications you own or have explicit written authorisation to test.**

- All payloads are **safe, non-destructive** test strings (no `DROP TABLE`, no real data modification)
- The tool uses a polite crawl delay (`0.3 s` by default) to avoid disrupting services
- A warning is displayed in the UI before every injection scan
- The User-Agent header is set to `AegisSecurity/1.0 Web Application Assessment` to identify the scanner

---

## Roadmap

- [ ] **Header/cookie injection** — extend `SQLiDetector` and `XSSDetector` to POST body and headers
- [ ] **Stored XSS detection** — second-request comparison after payload submission
- [ ] **CSRF detection** — check for missing anti-CSRF tokens on state-changing forms
- [ ] **Authentication support** — session cookie / Bearer token injection for authenticated scans
- [ ] **Scan history** — persist scan results to SQLite for historical comparison
- [ ] **Scheduled scans** — APScheduler integration for recurring assessments
- [ ] **CI/CD integration** — CLI entry point for pipeline usage
- [ ] **Selenium mode** — JavaScript-rendered page support for SPAs

---

## License

MIT — see `LICENSE` for details.

---

*Aegis Security Platform*