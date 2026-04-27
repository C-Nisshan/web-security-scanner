# ── Aegis Security Platform — Dockerfile ──────────────────────────────────
FROM python:3.11-slim

# System dependencies for lxml / requests / Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir reportlab flask-swagger-ui

# Install Playwright and its browser binaries
RUN pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# Copy application source
COPY . .

# Ensure reports directory exists
RUN mkdir -p reports

# Expose Flask port
EXPOSE 5000

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

# Health check so dependant services (if any) know when the API is ready
HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
    CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["python", "app.py"]