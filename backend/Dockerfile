# ── Aegis Security Platform — Dockerfile ──────────────────────────────────
FROM python:3.11-slim

# System dependencies for lxml / requests
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir reportlab flask-swagger-ui
RUN pip install playwright \
    && playwright install --with-deps

# Copy source code
COPY . .

# Create reports directory
RUN mkdir -p reports

# Expose Flask port
EXPOSE 5000

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

CMD ["python", "app.py"]