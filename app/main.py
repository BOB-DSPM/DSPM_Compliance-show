# app/main.py
from fastapi import FastAPI
from app.core.db import Base, engine
from app.routers import health, compliance

# 로컬/테스트: 스키마 자동 생성 (운영환경에선 마이그레이션 권장)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Compliance Mapping API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# 라우터
app.include_router(health.router, tags=["health"])
app.include_router(compliance.router, prefix="/compliance", tags=["compliance"])

# 로컬 실행 지원
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8003, reload=True)
