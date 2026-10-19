FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY phishshield ./phishshield
COPY docs ./docs
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
ENV PHISHSHIELD_HOST=0.0.0.0 PHISHSHIELD_PORT=8000 PHISHSHIELD_DB_PATH=/app/data/phishshield.sqlite3 PHISHSHIELD_INSPECT_ENABLED=false
CMD ["sh", "-c", "uvicorn phishshield.web:app --host 0.0.0.0 --port ${PORT:-8000}"]
