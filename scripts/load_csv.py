# load_csv_dynamic.py
import pandas as pd
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import Engine

# === 환경설정 (여기만 프로젝트에 맞게 수정) ===
DB_URL = "postgresql+psycopg2://USER:PASS@HOST:5432/DBNAME"
TABLE_NAME = 'compliance_mapping'      # 기존 테이블명
CSV_PATH = 'your_file.csv'             # 업로드할 CSV 경로
CHUNK = 10_000                         # 대용량일 때 청크 크기

# === 함수들 ===
def quote_ident(name: str) -> str:
    """Postgres에서 한글/공백/특수문자 컬럼명 안전하게 감싸기"""
    return '"' + name.replace('"', '""') + '"'

def add_missing_columns(engine: Engine, table: str, csv_cols: list[str]) -> None:
    insp = inspect(engine)
    existing_cols = {col['name'] for col in insp.get_columns(table)}
    missing = [c for c in csv_cols if c not in existing_cols]
    if not missing:
        return
    with engine.begin() as conn:
        for col in missing:
            # 기본 타입은 TEXT. 필요하면 맵핑 규칙으로 세분화 가능.
            sql = f'ALTER TABLE {quote_ident(table)} ADD COLUMN {quote_ident(col)} TEXT;'
            conn.execute(text(sql))
    print(f"[INFO] Added columns: {missing}")

def load_csv(engine: Engine, table: str, csv_path: str, chunk_size: int = 10000):
    # 문자열로 읽어서 타입 문제 최소화
    df_iter = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,   # 빈칸을 NaN 대신 빈 문자열로
        na_values=[],
        encoding='utf-8-sig'
    )

    # 헤더만 먼저 확인해서 컬럼 자동 추가
    if isinstance(df_iter, pd.DataFrame):
        header_cols = list(df_iter.columns)
        add_missing_columns(engine, table, header_cols)

        # 업로드
        df_iter.replace({"\u0000": ""}, regex=True, inplace=True)  # 널문자 방지
        df_iter.to_sql(table, engine, if_exists='append', index=False, method='multi', chunksize=chunk_size)
        print(f"[DONE] Uploaded {len(df_iter)} rows.")
    else:
        # pandas가 iterator를 반환하는 경우 (구버전 대응)
        first = next(df_iter)
        header_cols = list(first.columns)
        add_missing_columns(engine, table, header_cols)

        total = 0
        first.replace({"\u0000": ""}, regex=True, inplace=True)
        first.to_sql(table, engine, if_exists='append', index=False, method='multi', chunksize=chunk_size)
        total += len(first)
        for chunk in df_iter:
            chunk.replace({"\u0000": ""}, regex=True, inplace=True)
            chunk.to_sql(table, engine, if_exists='append', index=False, method='multi', chunksize=chunk_size)
            total += len(chunk)
        print(f"[DONE] Uploaded {total} rows.")

if __name__ == "__main__":
    engine = create_engine(DB_URL, pool_pre_ping=True, future=True)
    # CSV 컬럼에 따옴표/공백/한글이 포함되어도 그대로 컬럼명으로 사용합니다.
    load_csv(engine, TABLE_NAME, CSV_PATH, CHUNK)
