# A-HIDS Server + Dashboard Dockerfile
# Multi-stage build: Stage 1 = build dependencies, Stage 2 = runtime image

# ── Stage 1: Build ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Create directories for data and certs
RUN mkdir -p /app/data /app/certs /app/logs

# Expose API port and dashboard port
EXPOSE 5000 8080

# Default environment variables (override via docker-compose or -e flags)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Default command: run the server
CMD ["python", "server/main.py"]
