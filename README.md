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
- [Testing with Swagger UI](#testing-with-swagger-ui)
- [Testing with the Frontend](#testing-with-the-frontend)
- [Docker Setup (Windows)](#docker-setup-windows)
- [API Reference](#api-reference)
- [Module Documentation](#module-documentation)
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
| **REST API** | Flask backend with Swagger UI for interactive testing |
| **Web UI** | Full assessment console with Discovery, Injection, and Full Scan tabs |

---

## Architecture

```
User (Browser) ──► Frontend (HTML/CSS/JS)   ──► Swagger UI (/api/docs)
                        │                              │
                        ▼ REST API calls               │
                   Flask app.py  ◄─────────────────────┘
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
playwright install
```

---

## Running the Application

### Start the Flask backend

```bash
python app.py
```

The API server starts at `http://127.0.0.1:5000`.

### Open the frontend

```bash
cd frontend
python -m http.server 8080
```

Then visit `http://localhost:8080`.

---

## Testing with Swagger UI

Swagger UI provides a full interactive API console directly in the browser — no frontend or curl commands required.

### Step 1 — Start the backend

```bash
python app.py
```

### Step 2 — Open Swagger UI

Navigate to:

```
http://127.0.0.1:5000/api/docs
```

You will see all endpoints grouped by tag (health, discovery, injection, full-scan, reports).

### Step 3 — Run the health check

1. Click **GET /api/health** to expand it.
2. Click **Try it out** → **Execute**.
3. Confirm the response shows `"status": "ok"`.

### Step 4 — Run a surface discovery scan

1. Expand **POST /api/scan/crawl**.
2. Click **Try it out**.
3. Edit the request body — replace the example URL with your target:
```json
   {
     "target_url": "http://localhost:3000",
     "max_depth": 2,
     "max_urls": 40
   }
```
4. Click **Execute** and inspect the `visited_urls` array in the response.

### Step 5 — Run a full pipeline scan

1. Expand **POST /api/scan/full**.
2. Click **Try it out** and enter:
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
3. Click **Execute**. Note the `scan_id` in the response (e.g. `"a1b2c3d4"`).

### Step 6 — Download the report

1. Expand **GET /api/report/{scan_id}/html**.
2. Click **Try it out**, paste your `scan_id`, and click **Execute**.
3. Click the **Download file** link that appears in the response to save the report.

> The raw OpenAPI JSON spec is also available at `http://127.0.0.1:5000/api/swagger.json` if you want to import it into Postman or Insomnia.

---

## Testing with the Frontend

The frontend is a static HTML/CSS/JS application that communicates with the Flask backend.

### Step 1 — Ensure the backend is running

```bash
python app.py
# Backend available at http://127.0.0.1:5000
```

### Step 2 — Serve the frontend

```bash
cd frontend
python -m http.server 8080
```

Open `http://localhost:8080` in your browser.

### Step 3 — Use the Assessment Console

Navigate to **Scanner** (`http://localhost:8080/scanner.html`). The console has three tabs:

| Tab | What it does |
|-----|-------------|
| **Discovery** | Runs the crawler and lists every page found |
| **Injection** | Tests a single URL with SQLi / XSS payloads |
| **Full Scan** | Runs the complete pipeline and generates a downloadable report |

**Recommended workflow:**

1. Start with **Discovery** — enter your target URL and click *Start Discovery*.
2. After the crawl completes, switch to **Full Scan** (the target URL is pre-filled).
3. Click *Run Full Scan* and wait for all four stages to complete.
4. Use the **HTML Report** and **PDF Report** buttons to download your findings.

---

## Docker Setup (Windows)

Docker lets you run the Aegis backend and intentionally vulnerable test targets without installing anything locally.

### Step 1 — Install Docker Desktop on Windows

1. Visit [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) and download the installer.
2. Run `Docker Desktop Installer.exe` and follow the prompts.
3. When prompted, enable **WSL 2** integration (recommended) or **Hyper-V** backend.
4. Restart your PC if prompted.
5. Launch **Docker Desktop** from the Start menu and wait for the whale icon in the system tray to become steady (not animating).

Verify the installation in PowerShell:

```powershell
docker --version
docker compose version
```

### Step 2 — Clone the repository

```powershell
git clone https://github.com/your-username/aegis-security.git
cd aegis-security
```

### Step 3 — Build and start all services

```powershell
docker compose up --build
```

This starts three containers:

| Container | Address | Purpose |
|-----------|---------|---------|
| `aegis-backend` | `http://localhost:5000` | Aegis Flask API + Swagger UI |
| `juice-shop` | `http://localhost:3000` | OWASP Juice Shop (safe test target) |
| `dvwa` | `http://localhost:8080` | DVWA (safe test target) |

### Step 4 — Verify everything is running

```powershell
curl http://localhost:5000/api/health
```

Expected:
```json
{"status": "ok", "service": "Aegis Security Platform", ...}
```

Open Swagger UI at `http://localhost:5000/api/docs`.

### Step 5 — Run a test scan against Juice Shop

In Swagger UI or PowerShell:

```powershell
curl -X POST http://localhost:5000/api/scan/full `
  -H "Content-Type: application/json" `
  -d '{"target_url":"http://juice-shop:3000","max_depth":2,"max_urls":30}'
```

> **Note:** When running inside Docker, use the service name `juice-shop` instead of `localhost` as the hostname, because all containers share the same Docker network.

When testing from **outside** Docker (e.g. from your browser or PowerShell on the host), use `http://localhost:3000`.

### Step 6 — Stop all containers

```powershell
docker compose down
```

Reports are saved to `./reports/` on your host machine via the volume mount.

### Running only the backend (without test targets)

```powershell
docker compose up --build aegis-backend
```

### Rebuilding after code changes

```powershell
docker compose up --build --force-recreate aegis-backend
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

---

### `POST /api/scan/payload`
Injection assessment against a single URL.

```json
{
  "target_url":   "https://example.com/page?id=1",
  "payload_type": "both",
  "max_payloads": 20
}
```

---

### `POST /api/scan/full`
Full pipeline — crawl → inject → analyse → report.

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

---

### `GET /api/report/<scan_id>/html`
Download the standalone HTML report.

### `GET /api/report/<scan_id>/pdf`
Download the PDF report (requires `reportlab`).

### `GET /api/report/<scan_id>/summary`
JSON summary of a completed scan.

### `GET /api/docs`
**Swagger UI** — interactive API documentation and testing console.

### `GET /api/swagger.json`
Raw OpenAPI 3.0 specification (importable into Postman / Insomnia).

---

## Module Documentation

*(unchanged from original — see individual source files)*

---

## Testing

Test against intentionally vulnerable applications **only**.

| Target | Docker command |
|--------|----------------|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `docker run -p 3000:3000 bkimminich/juice-shop` |
| [DVWA](https://github.com/digininja/DVWA) | `docker run -p 8080:80 vulnerables/web-dvwa` |
| [WebGoat](https://github.com/WebGoat/WebGoat) | `docker run -p 8081:8080 webgoat/goat-and-wolf` |

Or spin up all test targets at once with `docker compose up`.

---

## Ethics & Responsible Use

> **Only run scans against applications you own or have explicit written authorisation to test.**

- All payloads are **safe, non-destructive** test strings
- The tool uses a polite crawl delay (`0.3 s` by default)
- A warning is displayed in the UI before every injection scan
- The User-Agent header identifies the scanner: `AegisSecurity/1.0 Web Application Assessment`

---

## Roadmap

- [ ] Header/cookie injection support
- [ ] Stored XSS detection
- [ ] CSRF detection
- [ ] Authentication support (session cookie / Bearer token)
- [ ] Scan history (SQLite persistence)
- [ ] Scheduled scans (APScheduler)
- [ ] CI/CD CLI entry point
- [ ] Selenium mode for JavaScript-rendered SPAs

---

## License

MIT — see `LICENSE` for details.

---

*Aegis Security Platform*