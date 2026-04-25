# Aegis Security — Automated Web Application Security Scanner

A Python-based educational tool that automatically crawls a web application, discovers input points, tests for common vulnerabilities (SQL Injection and Cross-Site Scripting), and generates a professional HTML or PDF assessment report with severity ratings and remediation guidance.

> **Educational Project Notice**
> This tool is intended for local use only against intentionally vulnerable practice applications such as OWASP Juice Shop and DVWA. It is not designed, intended, or supported for use against public websites, third-party services, or any system you do not own or have explicit written authorisation to test.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start — Docker (Recommended)](#quick-start--docker-recommended)
- [Manual Setup (Alternative)](#manual-setup-alternative)
- [URL Reference — Docker vs Browser](#url-reference--docker-vs-browser)
- [Testing with Swagger UI](#testing-with-swagger-ui)
- [Testing with the Frontend](#testing-with-the-frontend)
- [API Reference](#api-reference)
- [Module Documentation](#module-documentation)
- [Ethics and Responsible Use](#ethics-and-responsible-use)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Module | Description |
|--------|-------------|
| Surface Discovery | Breadth-first crawler maps all reachable pages up to a configurable depth |
| SQL Injection | Error-based, boolean-based, and time-based detection |
| XSS Detection | Reflected XSS with context analysis (HTML body, attribute, script block) |
| Response Analysis | Aggregates findings, assigns CVSS-inspired severity scores |
| HTML Report | Standalone, self-contained dark-themed report |
| PDF Report | Professional PDF via ReportLab with cover page, findings, and remediation |
| REST API | Flask backend with Swagger UI for interactive testing |
| Web UI | Full assessment console with Discovery, Injection, and Full Scan tabs |

---

## Architecture

```
User (Browser) ---> Frontend (HTML/CSS/JS)   ---> Swagger UI (/api/docs)
                        |                              |
                        v  REST API calls              |
                   Flask app.py  <--------------------/
                        |
          .-------------+--------------.
          v             v              v
      Crawler    PayloadEngine   ScannerController
                                      |
                          .-----------+-----------.
                          v           v           v
                    SQLiDetector  XSSDetector   (future)
                          |           |
                          `------.----'
                                 v
                         ResponseAnalyzer
                                 |
                                 v
                         ReportGenerator
                          (HTML + PDF)
```

---

## Project Structure

```
web-security-scanner/
├── backend/
│   ├── app.py                    # Flask REST API server + Swagger setup
│   ├── swagger.py                # OpenAPI 3.0 specification
│   ├── requirements.txt          # Python dependencies
│   ├── Dockerfile                # Container image definition
│   ├── docker-compose.yml        # Multi-container stack (backend + test targets)
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── crawler.py
│   │   ├── payload_engine.py
│   │   ├── sqli_detector.py
│   │   ├── xss_detector.py
│   │   ├── response_analyzer.py
│   │   ├── report_generator.py
│   │   └── controller.py
│   │
│   └── reports/                  # Generated reports (auto-created)
│
├── frontend/
│   ├── index.html
│   ├── about.html
│   ├── services.html
│   ├── contact.html
│   ├── scanner.html
│   ├── css/
│   └── js/
│
├── images/
│   └── logo.svg
│
├── .gitignore
└── README.md
```

---

## Quick Start -- Docker (Recommended)

Docker is the recommended way to run Aegis Security. It starts the backend, OWASP Juice Shop, and DVWA in a single command with no manual dependency installation required.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop) installed and running
- Git

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-username/aegis-security.git
cd aegis-security
```

### Step 2 — Start all services

```bash
docker compose up --build
```

This starts three containers:

| Container | Browser URL | Purpose |
|-----------|-------------|---------|
| `aegis-backend` | http://localhost:5000 | Aegis Flask API + Swagger UI |
| `juice-shop` | http://localhost:3000 | OWASP Juice Shop (test target) |
| `dvwa` | http://localhost:8080 | DVWA (test target) |

### Step 3 — Verify the backend is running

```bash
curl http://localhost:5000/api/health
```

Expected response:

```json
{"status": "ok", "service": "Aegis Security Platform"}
```

Open Swagger UI at: `http://localhost:5000/api/docs`

### Step 4 — Serve the frontend

In a separate terminal:

```bash
cd frontend
python -m http.server 8080
```

Then open `http://localhost:8080` in your browser and navigate to the Scanner page.

### Step 5 — Run a test scan

In the Scanner console, enter the Juice Shop URL and run a Full Scan:

- **From the browser / Swagger UI (outside Docker):** use `http://localhost:3000`
- **From the backend container (inside Docker):** use `http://juice-shop:3000`

See the [URL Reference](#url-reference--docker-vs-browser) section for a full explanation.

### Step 6 — Stop all containers

```bash
docker compose down
```

Generated reports are saved to `./reports/` on your host machine via the Docker volume mount.

---

## Manual Setup (Alternative)

Use this method if you prefer to run the backend directly on your machine without Docker.

### Prerequisites

- Python 3.10 or higher
- pip

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-username/aegis-security.git
cd aegis-security
```

### Step 2 — Create a virtual environment

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
playwright install
```

### Step 4 — Start the backend

```bash
python app.py
```

The API server starts at `http://127.0.0.1:5000`.

### Step 5 — Start the test targets (optional but recommended)

You still need Docker for the vulnerable test applications:

```bash
docker run -p 3000:3000 bkimminich/juice-shop
docker run -p 8080:80 vulnerables/web-dvwa
```

### Step 6 — Serve the frontend

In a separate terminal:

```bash
cd frontend
python -m http.server 8080
```

Then open `http://localhost:8080`.

---

## URL Reference -- Docker vs Browser

This is the most common source of confusion when running Aegis with Docker.

Docker containers communicate with each other using **service names** defined in `docker-compose.yml`, not `localhost`. Your browser, however, always uses `localhost` to reach ports forwarded to your host machine.

| Where you are typing the URL | Correct URL to use |
|------------------------------|--------------------|
| Browser (Scanner page, Swagger UI) | `http://localhost:3000` |
| Backend container scanning Juice Shop | `http://juice-shop:3000` |
| Browser scanning DVWA | `http://localhost:8080` |
| Backend container scanning DVWA | `http://dvwa:80` |

**Practical rule:**

- If you are entering a URL into your **browser** or the **Scanner web UI**, use `localhost`.
- If you are sending a scan request directly to the Aegis API (e.g. via curl from your terminal or Swagger UI), and the scan target is also running in Docker, use the **Docker service name**.

When you use the Scanner web UI in your browser, the frontend sends the target URL to the Aegis backend, which then performs the actual scan. The backend runs inside Docker, so it must use the Docker service name to reach other containers.

**Example:**

You want to scan Juice Shop using the web UI. Enter `http://localhost:3000` in the Scanner URL field. The browser cannot use `juice-shop:3000`, but the Aegis backend (which is inside Docker) can reach Juice Shop at `http://juice-shop:3000` internally.

To scan Juice Shop entirely within Docker (e.g. via the API directly), use `http://juice-shop:3000` as the target URL.

---

## Testing with Swagger UI

Swagger UI provides a full interactive API console in the browser with no additional tooling required.

### Step 1 — Start the backend

```bash
# Docker
docker compose up --build

# Manual
python app.py
```

### Step 2 — Open Swagger UI

```
http://localhost:5000/api/docs
```

### Step 3 — Health check

1. Expand `GET /api/health`.
2. Click `Try it out` then `Execute`.
3. Confirm the response shows `"status": "ok"`.

### Step 4 — Surface discovery scan

1. Expand `POST /api/scan/crawl` and click `Try it out`.
2. Enter a target URL. If running in Docker and scanning Juice Shop from within the container network, use `http://juice-shop:3000`. If scanning via the browser/Swagger UI, use `http://localhost:3000`.

```json
{
  "target_url": "http://localhost:3000",
  "max_depth": 2,
  "max_urls": 40
}
```

3. Click `Execute` and inspect the `visited_urls` array in the response.

### Step 5 — Full pipeline scan

1. Expand `POST /api/scan/full` and click `Try it out`.

```json
{
  "target_url": "http://localhost:3000",
  "max_depth": 2,
  "max_urls": 40,
  "max_targets": 10,
  "max_payloads": 20,
  "payload_type": "both"
}
```

2. Click `Execute`. Note the `scan_id` returned in the response (for example, `"a1b2c3d4"`).

### Step 6 — Download the report

1. Expand `GET /api/report/{scan_id}/html`.
2. Click `Try it out`, enter your `scan_id`, and click `Execute`.
3. Click the `Download file` link in the response to save the report.

The raw OpenAPI JSON specification is available at `http://localhost:5000/api/swagger.json` for import into Postman or Insomnia.

---

## Testing with the Frontend

The frontend is a static HTML/CSS/JS application that communicates with the Flask backend over the REST API.

### Step 1 — Ensure the backend is running

```bash
# Docker (recommended)
docker compose up --build

# Manual
python app.py
```

### Step 2 — Serve the frontend

```bash
cd frontend
python -m http.server 8080
```

Open `http://localhost:8080` in your browser.

### Step 3 — Use the Assessment Console

Navigate to the Scanner page (`http://localhost:8080/scanner.html`). The console has three tabs:

| Tab | What it does |
|-----|--------------|
| Discovery | Runs the crawler and lists every page found |
| Injection | Tests a single URL with SQLi and XSS payloads |
| Full Scan | Runs the complete pipeline and generates a downloadable report |

### Recommended workflow

1. In the **Discovery** tab, enter your target URL and click `Start Discovery`.

   - Always use `http://localhost:3000` (or `http://localhost:8080` for DVWA) when typing into the browser-based UI.
   - Do not use Docker service names (`juice-shop:3000`) in the browser — these are only valid inside the Docker network.

2. After the crawl completes, the target URL is automatically pre-filled in the other tabs. Switch to **Full Scan**.

3. Click `Run Full Scan` and wait for the pipeline to complete.

4. Use the `HTML Report` and `PDF Report` buttons to download your findings.

---

## API Reference

### `GET /api/health`

Health check. Returns service status.

---

### `POST /api/scan/crawl`

Surface discovery only. Crawls the target and returns all reachable pages.

**Request body:**

```json
{
  "target_url": "http://localhost:3000",
  "max_depth":  2,
  "max_urls":   40
}
```

---

### `POST /api/scan/payload`

Injection assessment against a single URL. Tests the specified URL with SQLi and/or XSS payloads.

**Request body:**

```json
{
  "target_url":   "http://localhost:3000/page?id=1",
  "payload_type": "both",
  "max_payloads": 20
}
```

---

### `POST /api/scan/full`

Full pipeline: crawl, inject, analyse, and generate report.

**Request body:**

```json
{
  "target_url":   "http://localhost:3000",
  "max_depth":    2,
  "max_urls":     40,
  "max_targets":  10,
  "max_payloads": 20,
  "payload_type": "both"
}
```

---

### `GET /api/report/<scan_id>/html`

Download the standalone HTML report for a completed scan.

### `GET /api/report/<scan_id>/pdf`

Download the PDF report. Requires `reportlab` to be installed.

### `GET /api/report/<scan_id>/summary`

JSON summary of a completed scan.

### `GET /api/docs`

Swagger UI — interactive API documentation and testing console.

### `GET /api/swagger.json`

Raw OpenAPI 3.0 specification.

---

## Module Documentation

| Module | Layer | Responsibility |
|--------|-------|----------------|
| `crawler.py` | Processing | BFS crawl with static HTML parsing and Playwright JS fallback |
| `payload_engine.py` | Processing | GET and POST injection across SQLi and XSS payload sets |
| `sqli_detector.py` | Processing | Error-based, boolean-based, and time-based SQL injection detection |
| `xss_detector.py` | Processing | Context-aware reflected XSS detection across HTML body, attribute, and script contexts |
| `response_analyzer.py` | Analysis | Aggregates findings, assigns CVSS-inspired severity scores, adds OWASP references |
| `report_generator.py` | Reporting | Generates standalone HTML and PDF reports via ReportLab |
| `controller.py` | Orchestration | Runs the four-stage pipeline (crawl, extract, inject, analyse, report) |
| `app.py` | API | Flask REST server, route definitions, Swagger UI registration |

For implementation details, refer to the docstrings at the top of each source file.

---

## Test Targets

Only scan intentionally vulnerable applications that exist for practice and education.

| Application | Docker command | Browser URL |
|-------------|---------------|-------------|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `docker run -p 3000:3000 bkimminich/juice-shop` | `http://localhost:3000` |
| [DVWA](https://github.com/digininja/DVWA) | `docker run -p 8080:80 vulnerables/web-dvwa` | `http://localhost:8080` |
| [WebGoat](https://github.com/WebGoat/WebGoat) | `docker run -p 8081:8080 webgoat/goat-and-wolf` | `http://localhost:8081` |

All three are also available by running `docker compose up` from this repository.

---

## Ethics and Responsible Use

Only run scans against applications you own or have explicit written authorisation to test.

This tool is built for educational use in controlled, local environments. The following design decisions reflect that intent:

- All payloads are safe, non-destructive, read-only test strings. No DDL or DML mutations are used.
- The crawler uses a polite request delay (0.3 seconds by default) to avoid overwhelming a target.
- The Scanner UI displays a warning before each injection scan reminding users to verify authorisation.
- The User-Agent header identifies the tool: `AegisSecurity/1.0 Web Application Assessment`.
- No scan data is transmitted to external services. Everything runs locally.

Scanning public websites, production systems, or any system without written permission is illegal in most jurisdictions and is not a supported use case for this tool.

---

## Roadmap

- [ ] Header and cookie injection support
- [ ] Stored XSS detection
- [ ] CSRF detection
- [ ] Authentication support (session cookie / Bearer token)
- [ ] Scan history with SQLite persistence
- [ ] Scheduled scans via APScheduler
- [ ] CI/CD CLI entry point
- [ ] Selenium mode for JavaScript-rendered SPAs

---

## License

MIT — see `LICENSE` for details.

---

*Aegis Security Platform — Educational Web Application Security Scanner*