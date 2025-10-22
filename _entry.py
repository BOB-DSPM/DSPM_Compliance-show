import os, subprocess, sys
from app.core.db import SessionLocal, Base, engine

# 테이블 생성 보장
Base.metadata.create_all(bind=engine)

def count_frameworks() -> int:
    try:
        from app.models import Framework
        with SessionLocal() as db:
            return db.query(Framework).count()
    except Exception:
        return 0

def maybe_seed():
    force = os.getenv("FORCE_SEED", "0") == "1"
    req_csv = os.getenv("REQUIREMENTS_CSV", "/app/compliance.csv")
    map_csv = os.getenv("MAPPINGS_CSV", "/app/mapping-standard.csv")
    cnt = count_frameworks()
    need = force or cnt == 0
    print(f"[i] framework_count={cnt}, force={force} -> need_seed={need}")
    if need:
        print(f"[i] seeding: req={req_csv}, map={map_csv}")
        subprocess.run(
            [sys.executable, "-m", "scripts.load_csv",
             "--requirements", req_csv, "--mappings", map_csv],
            check=True
        )
        print("[i] seed done")

def main():
    maybe_seed()
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = os.getenv("PORT", "8003")
    os.execvp(
        sys.executable,
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", host, "--port", str(port)]
    )

if __name__ == "__main__":
    main()
