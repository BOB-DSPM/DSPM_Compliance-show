# Dockerfile (간단/안정: _entry.py를 COPY)
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8003 \
    APP_HOST=0.0.0.0 \
    REQUIREMENTS_CSV=/app/compliance.csv \
    MAPPINGS_CSV=/app/mapping-standard.csv \
    FORCE_SEED=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# 앱/스크립트/CSV
COPY app /app/app
COPY scripts /app/scripts
COPY compliance.csv /app/compliance.csv
COPY compliance-gorn.csv /app/compliance-gorn.csv
COPY compliance-mapped.csv /app/compliance-mapped.csv
COPY mapping-standard.csv /app/mapping-standard.csv
COPY app.db /app/app.db

# 방금 만든 런처 파일을 복사
COPY _entry.py /app/_entry.py

# 비루트
RUN useradd -ms /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8003
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

CMD ["python", "/app/_entry.py"]
