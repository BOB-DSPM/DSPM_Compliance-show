# Dockerfile
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8003

# 런타임 유틸 (헬스체크용 curl 포함)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 설치 (캐시 최적화)
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# 앱 소스/DB 복사
COPY . /app

# 비루트 유저
RUN useradd -ms /bin/bash appuser \
 && chown -R appuser:appuser /app
USER appuser

# 포트 및 헬스체크
EXPOSE 8003
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

# FastAPI 실행
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
