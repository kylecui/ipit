# ============================================================
# TIRE - Threat Intelligence Reasoning Engine
# Multi-stage Docker build
# ============================================================

# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN groupadd -r tire && useradd -r -g tire -d /app -s /sbin/nologin tire

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/
COPY models/ ./models/
COPY collectors/ ./collectors/
COPY analyzers/ ./analyzers/
COPY normalizers/ ./normalizers/
COPY reporters/ ./reporters/
COPY storage/ ./storage/
COPY cache/ ./cache/
COPY rules/ ./rules/
COPY templates/ ./templates/
COPY locales/ ./locales/
COPY adapters/ ./adapters/
COPY enrichers/ ./enrichers/
COPY graph/ ./graph/

# Create directories for runtime data
RUN mkdir -p /app/data && chown -R tire:tire /app

# Switch to non-root user
USER tire

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO \
    CACHE_TTL_HOURS=24 \
    HTTP_TIMEOUT_SECONDS=15 \
    MAX_RETRIES=2

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--access-log"]
