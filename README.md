# Aegis Security Platform

Web application security assessment platform with automated surface discovery and injection testing.

---

## Folder Structure

```
web-security-scanner/
│
├── frontend/
│   ├── index.html               ← Home page
│   ├── about.html               ← About page
│   ├── services.html            ← Services page
│   ├── contact.html             ← Contact page
│   ├── scanner.html             ← Assessment console
│   │
│   ├── css/
│   │   ├── global.css           ← Shared: variables, navbar, footer, utilities
│   │   ├── index.css            ← Home page styles
│   │   ├── scanner.css          ← Scanner console styles
│   │   ├── about.css            ← About page styles
│   │   ├── services.css         ← Services page styles
│   │   └── contact.css          ← Contact page styles
│   │
│   └── js/
│       ├── global.js            ← Shared: navbar scroll, active link
│       ├── index.js             ← Home page logic
│       ├── scanner.js           ← Assessment console (crawl + inject)
│       ├── about.js             ← About page logic
│       ├── services.js          ← Services page logic
│       └── contact.js           ← Contact form handler
│
└── backend/
    ├── app.py                   ← Flask REST API (entry point)
    ├── requirements.txt
    ├── reports/                 ← Generated reports (runtime)
    └── scanner/
        ├── __init__.py
        ├── crawler.py           ← Surface Discovery Module
        ├── payload_engine.py    ← Injection Assessment Module
        ├── controller.py        ← Orchestrator (stub)
        ├── response_analyzer.py ← Response parser (stub)
        ├── report_generator.py  ← Report output (stub)
        └── detectors/
            ├── __init__.py
            ├── sqli_detector.py ← SQLi classifier (stub)
            └── xss_detector.py  ← XSS classifier (stub)
```

---

## Implemented Modules

### Surface Discovery — `crawler.py`

Breadth-first crawl of a target web application. Discovers all internal pages and links reachable from a seed URL.

**API:** `POST /api/scan/crawl`
```json
{ "target_url": "https://example.com", "max_depth": 2, "max_urls": 40 }
```

### Injection Assessment — `payload_engine.py`

Injects SQL Injection and XSS payloads into URL query parameters. Analyses HTTP responses for vulnerability signatures.

**API:** `POST /api/scan/payload`
```json
{ "target_url": "https://example.com/page?id=1", "payload_type": "both", "max_payloads": 20 }
```
`payload_type` accepts: `"sqli"` | `"xss"` | `"both"`

---

## Prerequisites
Python 3.8+  `python3 --version` |
VS Code 

---

## Setup (terminal in VS Code)

Open the project in VS Code then open the terminal.

```bash
# 1. Go to backend
cd web-security-scanner/backend

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate it  (you should see "(venv)" in your prompt)
source venv/bin/activate # for Linux
venv\Scripts\Activate # for windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify
python -c "import flask, requests, bs4; print('All OK')"
```

---

## Running

### Terminal 1 — Backend

```bash
cd web-security-scanner/backend
venv\Scripts\Activate
python app.py
```

Expected output:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### Terminal 2 — Frontend

**Option A — VS Code Live Server (recommended)**
Right-click `frontend/index.html` → **Open with Live Server**


## How to Use the Scanner

1. Navigate to `scanner.html`
2. **Discovery tab** — enter a real external URL (e.g. `https://books.toscrape.com`), set depth 2, max pages 40, click **Start Discovery**
3. **Injection tab** — paste a URL with a query parameter (e.g. `https://example.com/search?q=test`), choose a test profile, click **Run Assessment**

> ⚠ The crawler will crawl *itself* if you point it at `127.0.0.1:5500`. Always use an external target URL.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: flask` | Run `source venv/bin/activate` first |
| `NetworkError` on injection tab | Flask server is not running — start `python app.py` |
| Crawler finds your own files | You entered `127.0.0.1:5500` as the target. Use an external URL |
| `Address already in use: 5000` | Change port in `app.py` and update `API` constant in `scanner.js` |
| Logo not showing | Logo uses Bootstrap Icons — no image file needed; ensure Bootstrap Icons CDN loads |
