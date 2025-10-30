# migrate_sqlite_requirements.py  (SQLite 전용)

from sqlalchemy import create_engine, text

DB_URL = "sqlite:///./app.db"

SQL = """
PRAGMA foreign_keys=OFF;

BEGIN TRANSACTION;

ALTER TABLE requirements RENAME TO requirements_old;

CREATE TABLE requirements (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  framework_code     TEXT NOT NULL REFERENCES frameworks(code),
  item_code          VARCHAR(128),
  title              VARCHAR(512) NOT NULL,
  description        TEXT NOT NULL,
  mapping_status     VARCHAR(64),
  auditable          VARCHAR(64),
  audit_method       TEXT,
  recommended_fix    TEXT,
  applicable_compliance VARCHAR(16)
);

INSERT INTO requirements (
  id, framework_code, item_code, title, description,
  mapping_status, auditable, audit_method, recommended_fix, applicable_compliance
)
SELECT
  id, framework_code, item_code, title, description,
  mapping_status, auditable, audit_method, NULL, NULL
FROM requirements_old;

DROP TABLE requirements_old;

COMMIT;

PRAGMA foreign_keys=ON;
"""

CHECKS = [
    "PRAGMA integrity_check;",
    "PRAGMA foreign_key_check;",
    "SELECT count(*) AS n FROM requirements;",
    "PRAGMA table_info('requirements');",
]

if __name__ == "__main__":
    engine = create_engine(DB_URL, future=True)

    # executescript() 사용: 멀티문 실행 허용
    raw_conn = engine.raw_connection()
    try:
        cur = raw_conn.cursor()
        cur.executescript(SQL)
        raw_conn.commit()
    finally:
        raw_conn.close()

    # 검증 쿼리(단일문이므로 exec_driver_sql 사용 가능)
    with engine.begin() as conn:
        for q in CHECKS:
            res = conn.exec_driver_sql(q).fetchall()
            print(q, "->", res)
