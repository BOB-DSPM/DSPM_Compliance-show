# Compliance Mapping API Dockerfile
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8003 \
    APP_HOME=/app \
    APP_HOST=0.0.0.0 \
    REQUIREMENTS_CSV=/app/compliance-gorn.csv \
    MAPPINGS_CSV=/app/mapping-standard.csv \
    FORCE_SEED=0

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY _entry.py .

# Ship the latest seed data + SQLite DB (can be replaced by mounting a volume)
COPY compliance-gorn.csv compliance.csv compliance-mapped.csv mapping-standard.csv threat_groups.csv ./ 
COPY app.db ./app.db

RUN useradd -ms /bin/bash appuser && chown -R appuser:appuser ${APP_HOME}
USER appuser

EXPOSE ${PORT}
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
    CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

CMD ["python", "/app/_entry.py"]
