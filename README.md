# Aegis Security — Automated Web Application Security Scanner

A Python-based educational tool that automatically crawls a web application, discovers input points, tests for common vulnerabilities (SQL Injection and Cross-Site Scripting), and generates a professional HTML or PDF assessment report with severity ratings and AI-powered remediation guidance.

> **Educational Project Notice**
> This tool is intended for local use only against intentionally vulnerable practice applications such as OWASP Juice Shop and DVWA. It is not designed, intended, or supported for use against public websites, third-party services, or any system you do not own or have explicit written authorisation to test.

---

## What Changed in This Version

| Area | Change | Why |
|------|--------|-----|
| **DVWA login** | Added dedicated `dvwa-db` MySQL service with health check in `docker-compose.yml` | DVWA's bundled database was not ready before the scanner tried to log in, causing silent failures |
| **DVWA login** | `auth_manager.py` — `_dvwa_ensure_db()` now sleeps 3 s after setup POST; `login_dvwa()` retries up to 3 times | Handles the MySQL cold-start race condition |
| **PDF report** | Completely rewritten `report_generator.py` — proper A4 geometry, full-page dark cover, 5-column metric grid, calibrated table columns, severity left-rules, per-page footer | Previous PDF had alignment issues and did not meet industry-standard documentation conventions |
| **Recommendations** | New `scanner/ai_advisor.py` module — uses Google Gemini 1.5 Flash when `GEMINI_API_KEY` is set; falls back to enhanced rule-based advisor automatically | Produces context-aware, finding-specific recommendations instead of generic text |
| **Configuration** | `.env.example` added; `GEMINI_API_KEY` read from environment / Docker secret | Keeps API keys out of source control |
| **response_analyzer.py** | Delegates recommendation generation to `ai_advisor`; passes `scan_meta` for context | Required by the new advisor architecture |
| **Dockerfile** | Fixed broken `CMD` (Markdown link artifact); added `HEALTHCHECK`; Playwright installs Chromium only | Prevented container from crashing on start |
| **URL confusion** | This README now contains a comprehensive URL reference table and flow diagram | Most common support issue |
| **Port conflict** | Frontend served on **8088** (not 8080 which is used by DVWA) | Eliminated port clash when running all services |
| **Auth UI** | `scanner.html` updated — auth toggle panel added to all three tabs (Discovery, Injection, Full Scan) | Required DOM elements for `scanner.js` v3.1 auth functions |

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Quick Start — Docker (Recommended)](#quick-start--docker-recommended)
- [Manual Setup](#manual-setup)
- [⚠ URL Reference — Critical Reading](#️-url-reference--critical-reading)
- [Authentication Guide](#authentication-guide)
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
| AI Advisor | Gemini 1.5 Flash generates context-aware recommendations (falls back to rule-based) |
| HTML Report | Standalone, self-contained dark-themed report |
| PDF Report | Industry-standard PDF with cover page, metric grid, findings table, recommendations |
| Auth Manager | Cookie, Bearer, HTTP Basic, DVWA auto-login, generic form login |
| REST API | Flask backend with Swagger UI for interactive testing |
| Web UI | Full assessment console with Discovery, Injection, and Full Scan tabs |

---

## Architecture

```
Browser
  │
  ├── http://localhost:8088  →  Frontend (HTML/CSS/JS)
  │                                │
  │                                │  REST API calls to http://localhost:5000
  │                                ▼
  └── http://localhost:5000  →  aegis-backend (Flask)
                                   │
                     .─────────────┼──────────────.
                     ▼             ▼               ▼
                 Crawler    PayloadEngine    AuthManager
                                   │
                       .───────────┴──────────.
                       ▼                      ▼
               SQLiDetector            XSSDetector
                       │                      │
                       └──────────┬───────────┘
                                  ▼
                         ResponseAnalyzer
                                  │
                                  ▼
                             AIAdvisor ──► Gemini API (optional)
                                  │
                                  ▼
                         ReportGenerator
                          (HTML + PDF)

Docker internal network:
  aegis-backend ──► juice-shop:3000
  aegis-backend ──► dvwa:80
  dvwa          ──► dvwa-db:3306
```

---

## Project Structure

```
web-security-scanner/
│
├── .env.example                  # ← copy to .env and add your Gemini key
├── .env                          # ← YOU CREATE THIS (not committed to git)
├── .gitignore
├── README.md
│
├── backend/
│   ├── app.py                    # Flask REST API server
│   ├── swagger.py                # OpenAPI 3.0 specification
│   ├── requirements.txt          # Python dependencies
│   ├── Dockerfile                # Container image definition
│   ├── docker-compose.yml        # Multi-container stack
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── ai_advisor.py         # Gemini / rule-based recommendations
│   │   ├── auth_manager.py       # Authentication (cookie, bearer, DVWA, form)
│   │   ├── crawler.py
│   │   ├── payload_engine.py
│   │   ├── sqli_detector.py
│   │   ├── xss_detector.py
│   │   ├── response_analyzer.py  # delegates to ai_advisor
│   │   ├── report_generator.py   # PDF
│   │   └── controller.py
│   │
│   └── reports/                  # Generated reports (auto-created, volume-mounted)
│
└── frontend/
    ├── index.html
    ├── about.html
    ├── services.html
    ├── contact.html
    ├── scanner.html              # ← UPDATED: auth panels on all three tabs
    │
    ├── css/
    │   ├── global.css            # Global shared styles
    │   ├── index.css             # homepage-specific styles
    │   ├── about.css             # about page styles
    │   ├── services.css          # services page styles
    │   ├── contact.css           # contact page styles
    │   └── scanner.css           # Scanner UI styling
    │
    └── js/
        ├── global.js             # Shared JS utilities (nav, helpers)
        ├── app.js                # main app bootstrap / global logic
        ├── contact.js            # contact form handling & validation
        └── scanner.js            # v3.1 — auth, test-auth, scan phases
```

---

## Configuration

### Step 1 — Create your `.env` file

```bash
cp .env.example .env
```

Open `.env` and set your values:

```dotenv
# Required for AI-powered recommendations (optional — rule-based if blank)
GEMINI_API_KEY=your_key_here

# Flask
FLASK_ENV=production
```

### Step 2 — Get a Gemini API key (optional)

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Click **Create API key**.
3. Copy the key into `.env` as `GEMINI_API_KEY=`.

When the key is present, every full scan will send the confirmed findings to Gemini 1.5 Flash and receive tailored, prioritised recommendations. If the key is absent or the API call fails, the scanner automatically falls back to its built-in rule-based advisor — no action required.

### What the AI advisor does

With `GEMINI_API_KEY` set, the advisor receives:
- The target URL
- Each confirmed finding (type, severity, affected parameter, affected URL)

It returns 7–9 specific, prioritised recommendations written in a formal register suitable for a client report. Without the key, the built-in advisor returns structured recommendations based on the vulnerability types found (SQLi, XSS) plus general security hygiene guidance.

---

## Quick Start — Docker (Recommended)

Docker is the recommended way to run Aegis. One command starts the backend, a MySQL database for DVWA, DVWA itself, and OWASP Juice Shop.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop) installed and running
- Git

### Step 1 — Clone

```bash
git clone https://github.com/your-username/aegis-security.git
cd aegis-security
```

### Step 2 — Configure environment

```bash
cp .env.example .env
# Edit .env — add GEMINI_API_KEY if you want AI recommendations
```

### Step 3 — Start all services

```bash
cd backend
docker compose up --build
```

This starts four containers:

| Container | Internal name | Browser URL | Purpose |
|-----------|--------------|-------------|---------|
| `aegis-backend` | `aegis-backend` | http://localhost:5000 | Aegis Flask API + Swagger UI |
| `juice-shop` | `juice-shop` | http://localhost:3000 | OWASP Juice Shop (test target) |
| `dvwa` | `dvwa` | http://localhost:8080 | DVWA PHP frontend |
| `dvwa-db` | `dvwa-db` | *(internal only)* | DVWA MySQL database |

> **First run:** `dvwa-db` takes 15–30 seconds to initialise MySQL. The `dvwa` container waits for the health check to pass before starting. Wait until you see `aegis-backend` log `Running on http://0.0.0.0:5000` before proceeding.

### Step 4 — Verify the backend

```bash
curl http://localhost:5000/api/health
```

Expected:

```json
{"status": "ok", "service": "Aegis Security Platform"}
```

### Step 5 — Serve the frontend

Open a **second terminal**:

```bash
cd frontend
python -m http.server 8088
```

> **Use port 8088**, not 8080 — DVWA already occupies 8080.

Open your browser at `http://localhost:8088`.

### Step 6 — Stop all containers

```bash
docker compose down
```

To also remove the DVWA database volume (forces a fresh MySQL init next time):

```bash
docker compose down -v
```

Reports are saved to `./reports/` on your host via the Docker volume mount.

---

## Manual Setup

Use this if you prefer to run the backend outside Docker.

### Prerequisites

- Python 3.10 or higher
- pip

### Steps

```bash
# 1. Clone
git clone https://github.com/your-username/aegis-security.git
cd aegis-security

# 2. Virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Dependencies
pip install -r backend/requirements.txt
pip install google-generativeai   # optional — for AI recommendations
playwright install chromium

# 4. Environment
cp .env.example .env
# Edit .env

# 5. Start test targets (Docker still required for these)
docker run -d -p 3000:3000 bkimminich/juice-shop
docker run -d -p 8080:80 vulnerables/web-dvwa

# 6. Start backend
cd backend
python app.py
# API now at http://127.0.0.1:5000

# 7. Serve frontend (separate terminal)
cd frontend
python -m http.server 8088
# Open http://localhost:8088
```

---

## ⚠ URL Reference — Critical Reading

This is the most common source of confusion. Read this section before you run your first scan.

### The fundamental rule

**The Aegis backend container performs the actual crawling and scanning — not your browser.**

When you type a target URL into the Scanner UI, your browser sends it to the backend API (`localhost:5000`). The backend then uses that URL to make HTTP requests. Because the backend is a Docker container, it lives inside the Docker network. It cannot reach `localhost` on your host machine — it can only reach other containers by their **Docker service names**.

```
Your browser                    Docker network
     │                               │
     │  POST /api/scan/full          │
     │  { "target_url": "..." }      │
     │─────────────────────────────► │
     │                          aegis-backend
     │                               │
     │                               │ scans this URL ─────► juice-shop:3000
     │                               │                        dvwa:80
```

### URL cheat sheet

| Where you are typing | What you want to reach | URL to use |
|---------------------|----------------------|------------|
| Browser address bar (manual access) | Aegis backend API | `http://localhost:5000` |
| Browser address bar (manual access) | Swagger UI | `http://localhost:5000/api/docs` |
| Browser address bar (manual access) | Scanner frontend | `http://localhost:8088` |
| Browser address bar (manual access) | DVWA for manual login | `http://localhost:8080` |
| Browser address bar (manual access) | Juice Shop for manual use | `http://localhost:3000` |
| **Scanner UI — Target URL field** | **Scan Juice Shop** | **`http://juice-shop:3000`** |
| **Scanner UI — Target URL field** | **Scan DVWA** | **`http://dvwa:80`** |
| **Auth panel — DVWA Base URL** | **DVWA auto-login** | **`http://dvwa:80`** |
| Swagger UI — `target_url` field | Scan Juice Shop | `http://juice-shop:3000` |
| Swagger UI — `target_url` field | Scan DVWA | `http://dvwa:80` |
| `curl` from your terminal | Aegis health check | `http://localhost:5000/api/health` |

### Why can't I use localhost in the Scanner UI?

The Scanner UI runs in your browser. When you click "Run Full Scan", the browser sends a `POST` request to `http://localhost:5000/api/scan/full`. The backend receives this request and uses the `target_url` value to crawl. From inside the Docker container, `localhost` refers to the container itself — not your host machine and not other containers. The only way to reach Juice Shop or DVWA from inside the backend container is via their Docker service names (`juice-shop`, `dvwa`).

### When running backend manually (outside Docker)

If you ran the backend with `python app.py` instead of Docker Compose, the backend runs on your host machine. In that case you **can** use `localhost`:

| Target | URL to use |
|--------|-----------|
| Juice Shop | `http://localhost:3000` |
| DVWA | `http://localhost:8080` |

---

## Authentication Guide

The Scanner UI provides an Authentication panel on every tab (Discovery, Injection, Full Scan). Click **Authentication (optional)** to expand it.

### Auth types

| Type | Use case | Key fields |
|------|----------|------------|
| **None** | Unauthenticated scan | — |
| **Session Cookie** | You logged in manually via browser | Paste cookie string from DevTools → Application → Cookies |
| **Bearer Token** | JWT or API token | Paste token (without `Bearer ` prefix) |
| **HTTP Basic** | HTTP Basic Auth | Username + password |
| **DVWA Auto-Login** | Automated DVWA login | Base URL: `http://dvwa:80` · Username: `admin` · Password: `password` |
| **Generic Form Login** | Any form-based login | Login URL, field names, credentials |

### DVWA auto-login workflow

1. Open the **Full Scan** tab.
2. Set **Target URL** to `http://dvwa:80`.
3. Open **Authentication (optional)**.
4. Select **DVWA Auto-Login**.
5. Set **DVWA Base URL** to `http://dvwa:80` (not `localhost:8080`).
6. Click **Test Auth** — wait for the green badge: `Authentication succeeded — dvwa_form`.
7. Click **Run Full Scan**.

> If Test Auth fails with "still showing the login/setup page", the DVWA container may still be starting. Wait 30 seconds and try again.

### Session cookie workflow (manual login)

1. Open `http://localhost:8080` in your browser and log in to DVWA.
2. Open DevTools (F12) → Application → Cookies → `http://localhost:8080`.
3. Copy the value of `PHPSESSID`. Also copy `security` (usually `low`).
4. In the Scanner UI, select **Session Cookie** and paste:
   ```
   PHPSESSID=abc123; security=low
   ```
5. Set the target URL to `http://dvwa:80` and run your scan.

---

## Testing with Swagger UI

### Open Swagger UI

```
http://localhost:5000/api/docs
```

### Health check

1. Expand `GET /api/health` → Try it out → Execute.
2. Confirm `"status": "ok"`.

### Auth test (new in v3.1)

Before scanning, verify your credentials:

1. Expand `POST /api/auth/test` → Try it out.
2. Enter:

```json
{
  "auth": {
    "type": "dvwa",
    "base_url": "http://dvwa:80",
    "username": "admin",
    "password": "password",
    "security_level": "low"
  }
}
```

3. A `"success": true` response with a `PHPSESSID` cookie confirms DVWA login is working.

### Full pipeline scan

```json
{
  "target_url":   "http://juice-shop:3000",
  "max_depth":    2,
  "max_urls":     40,
  "max_targets":  10,
  "max_payloads": 20,
  "payload_type": "both"
}
```

Note the `scan_id` in the response, then download the report:

- `GET /api/report/{scan_id}/html`
- `GET /api/report/{scan_id}/pdf`

The raw OpenAPI spec is at `http://localhost:5000/api/swagger.json` for import into Postman or Insomnia.

---

## Testing with the Frontend

### Recommended workflow

1. Open `http://localhost:8088/scanner.html`.
2. Select the **Discovery** tab.
3. Enter the target URL — **use `http://juice-shop:3000`** (Docker service name).
4. Optionally expand **Authentication (optional)** and configure credentials.
5. Click **Test Auth** if using authentication, and confirm the green badge.
6. Click **Start Discovery**. The URL is auto-filled in the other tabs on success.
7. Switch to **Full Scan** and click **Run Full Scan**.
8. Download the HTML or PDF report when the scan completes.

### Port reference for the frontend

| Scan target | Enter this in Target URL |
|-------------|------------------------|
| OWASP Juice Shop | `http://juice-shop:3000` |
| DVWA | `http://dvwa:80` |

---

## API Reference

### `GET /api/health`

Health check.

### `POST /api/auth/test`

Validate authentication credentials without running a scan. Returns `"success": true/false` with cookie names and a detail message.

**Request:**

```json
{
  "auth": {
    "type": "dvwa",
    "base_url": "http://dvwa:80",
    "username": "admin",
    "password": "password",
    "security_level": "low"
  }
}
```

### `POST /api/scan/crawl`

Surface discovery only.

```json
{
  "target_url": "http://juice-shop:3000",
  "max_depth": 2,
  "max_urls": 40,
  "auth": { "type": "none" }
}
```

### `POST /api/scan/payload`

Injection assessment on a single URL.

```json
{
  "target_url":   "http://dvwa:80/vulnerabilities/sqli/?id=1&Submit=Submit",
  "payload_type": "both",
  "max_payloads": 20,
  "auth": {
    "type": "dvwa",
    "base_url": "http://dvwa:80",
    "username": "admin",
    "password": "password",
    "security_level": "low"
  }
}
```

### `POST /api/scan/full`

Full pipeline: crawl → inject → analyse → report.

```json
{
  "target_url":   "http://juice-shop:3000",
  "max_depth":    2,
  "max_urls":     40,
  "max_targets":  10,
  "max_payloads": 20,
  "payload_type": "both",
  "auth": { "type": "none" }
}
```

### `GET /api/report/<scan_id>/html`

Download the HTML report.

### `GET /api/report/<scan_id>/pdf`

Download the PDF report.

### `GET /api/report/<scan_id>/summary`

JSON summary of a completed scan.

### `GET /api/docs`

Swagger UI.

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
| `ai_advisor.py` | Analysis | Gemini 1.5 Flash recommendations (rule-based fallback) |
| `auth_manager.py` | Infrastructure | Session management for cookie, bearer, basic, DVWA, and form auth |
| `report_generator.py` | Reporting | Industry-standard HTML and PDF reports |
| `controller.py` | Orchestration | Runs the four-stage pipeline (crawl → inject → analyse → report) |
| `app.py` | API | Flask REST server, route definitions, Swagger UI |

---

## Test Targets

Only scan intentionally vulnerable applications that exist for practice and education.

| Application | Docker service name | Browser URL | Scan URL (from backend) |
|-------------|-------------------|-------------|------------------------|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `juice-shop` | `http://localhost:3000` | `http://juice-shop:3000` |
| [DVWA](https://github.com/digininja/DVWA) | `dvwa` | `http://localhost:8080` | `http://dvwa:80` |

---

## Ethics and Responsible Use

Only run scans against applications you own or have explicit written authorisation to test.

- All payloads are safe, non-destructive, read-only test strings.
- The crawler uses a polite request delay (0.3 s) to avoid overwhelming a target.
- The Scanner UI displays a warning before each injection scan.
- The User-Agent header identifies the tool: `AegisSecurity/1.0 Web Application Assessment`.
- No scan data is transmitted to external services except (optionally) the list of finding types sent to the Gemini API for recommendation generation — no URLs, no evidence strings, no personal data.

Scanning public websites, production systems, or any system without written permission is illegal in most jurisdictions.

---

## Roadmap

- [x] Authentication support (cookie, bearer, basic, DVWA, form)
- [x] AI-powered recommendations via Gemini
- [x] Industry-standard PDF report
- [ ] Header and cookie injection support
- [ ] Stored XSS detection
- [ ] CSRF detection
- [ ] Scan history with SQLite persistence
- [ ] Scheduled scans via APScheduler
- [ ] CI/CD CLI entry point

---

## License

MIT — see `LICENSE` for details.

---

*Aegis Security Platform — Web Application Security Scanner*