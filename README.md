# Aegis Security — Web Application Security Scanner

An automated scanner that crawls a web application, tests for SQL Injection and XSS vulnerabilities, and produces an HTML or PDF assessment report with AI-powered remediation guidance.

> **For educational use only.** Run scans only against intentionally vulnerable practice applications (OWASP Juice Shop, DVWA) that you own or host locally. Scanning systems without explicit written authorisation is illegal.

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop) installed and running
- Git

If Docker is not available, see [Manual Setup](#manual-setup) at the end of this document.

---

## 1. Environment Setup

```bash
git clone https://github.com/C-Nisshan/web-security-scanner.git
cd web-security-scanner
cp .env.example .env
```

Open `.env` and set your values:

```dotenv
# Optional — enables AI-powered recommendations via Gemini 1.5 Flash.
# Leave blank to use the built-in rule-based advisor instead.
GEMINI_API_KEY=your_key_here

FLASK_ENV=production
```

To get a Gemini key: visit [Google AI Studio](https://aistudio.google.com/app/apikey) → **Create API key** → paste into `.env`.

---

## 2. Start Services (Docker)

```bash
cd backend
docker compose up --build
```

This starts four containers:

| Service | Purpose | URL |
|---------|---------|-----|
| `aegis-backend` | Aegis scanner API | `http://localhost:5000` |
| `juice-shop` | OWASP Juice Shop (scan target) | `http://localhost:3000` |
| `dvwa` | DVWA (scan target) | `http://localhost:8080` |
| `dvwa-db` | DVWA database | *(internal only)* |

Wait until the logs show `Running on http://0.0.0.0:5000` before continuing.

> **First run:** `dvwa-db` takes 15–30 seconds to initialise. If DVWA login fails immediately after starting, wait 30 seconds and retry.

### Stop services

```bash
docker compose down
```

To also wipe the DVWA database (forces a clean re-initialisation next time):

```bash
docker compose down -v
```

---

## 3. Start the Frontend

Open a **second terminal**:

```bash
cd frontend
python -m http.server 8088
```
If this command does not work, try this:

```
python3 -m http.server 8088
```

Open your browser at **`http://localhost:8088`**.

> Use port **8088**, not 8080 — DVWA already occupies 8080.

### ⚠ Target URL — Critical

The scanner backend runs inside Docker. When it scans a target, it uses the **Docker service name**, not `localhost`. Enter the wrong URL and the scan will fail silently.

| What you want to scan | Enter this in the Target URL field |
|-----------------------|------------------------------------|
| OWASP Juice Shop | `http://juice-shop:3000` |
| DVWA | `http://dvwa:80` |

Your browser still accesses Juice Shop and DVWA via `localhost:3000` and `localhost:8080` for manual browsing — only the **scanner's Target URL field** must use the service names above.

### Running a scan

1. Open `http://localhost:8088/scanner.html`.
2. Go to the **Discovery** tab. Enter `http://juice-shop:3000` as the target.
3. Click **Start Discovery**. The URL carries over to the other tabs automatically.
4. Switch to **Full Scan** → click **Run Full Scan**.
5. Download the HTML or PDF report when the scan completes.

### Using authentication (DVWA)

1. Go to **Full Scan** → expand **Authentication (optional)**.
2. Select **DVWA Auto-Login**.
3. Set **DVWA Base URL** to `http://dvwa:80`.
4. Click **Test Auth** and confirm the green badge before scanning.

Other supported auth types: Session Cookie, Bearer Token, HTTP Basic, Generic Form Login.

---

## 4. Testing with Swagger UI

Swagger UI lets you call the API directly in the browser and inspect requests and responses.

Open: **`http://localhost:5000/api/docs`**

### Verify the backend is running

Expand `GET /api/health` → **Try it out** → **Execute**.  
Expected response: `{"status": "ok", "service": "Aegis Security Platform"}`

### Test authentication before scanning

Expand `POST /api/auth/test` → **Try it out** → paste this body → **Execute**:

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

A `"success": true` response confirms DVWA login is working.

### Run a full scan

Expand `POST /api/scan/full` → **Try it out** → paste this body → **Execute**:

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

Copy the `scan_id` from the response, then download your report:

- `GET /api/report/{scan_id}/html`
- `GET /api/report/{scan_id}/pdf`

> The raw OpenAPI spec at `http://localhost:5000/api/swagger.json` can be imported into Postman or Insomnia.

---

## Manual Setup

Use this only if Docker is not available. You still need Docker to run the scan targets (Juice Shop and DVWA).

```bash
# 1. Clone and enter the repo
git clone https://github.com/your-username/aegis-security.git
cd aegis-security

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r backend/requirements.txt
pip install google-generativeai  # optional, for AI recommendations
playwright install chromium

# 4. Configure environment
cp .env.example .env
# Edit .env and add GEMINI_API_KEY if desired

# 5. Start the scan targets (still requires Docker for these)
docker run -d -p 3000:3000 bkimminich/juice-shop
docker run -d -p 8080:80 vulnerables/web-dvwa

# 6. Start the backend
cd backend
python app.py
# API is now available at http://127.0.0.1:5000

# 7. Serve the frontend (separate terminal)
cd frontend
python -m http.server 8088
# Open http://localhost:8088
```

### Target URLs when running manually

Because the backend runs on your host (not inside Docker), use `localhost` directly:

| Target | URL to enter in the scanner |
|--------|-----------------------------|
| OWASP Juice Shop | `http://localhost:3000` |
| DVWA | `http://localhost:8080` |

---

## Ethics and Responsible Use

- Only scan applications you own or have explicit written authorisation to test.
- All payloads are non-destructive, read-only test strings.
- The scanner identifies itself via the `User-Agent` header: `AegisSecurity/1.0 Web Application Assessment`.
- If a Gemini API key is set, only confirmed finding *types* (not URLs or evidence strings) are sent to the Gemini API for recommendation generation.

---

## License

MIT — see `LICENSE` for details.
