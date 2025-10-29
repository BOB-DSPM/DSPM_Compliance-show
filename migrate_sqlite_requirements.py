# migrate_sqlite_requirements.py
from sqlalchemy import create_engine

DB_URL = "sqlite:///./app.db"

SQL = r"""
PRAGMA foreign_keys=OFF;

BEGIN TRANSACTION;

-- 기존 requirements를 최신 스키마로 재생성
ALTER TABLE requirements RENAME TO requirements_old;

CREATE TABLE requirements (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  framework_code          TEXT NOT NULL REFERENCES frameworks(code),
  item_code               VARCHAR(128),
  title                   VARCHAR(512) NOT NULL,
  description             TEXT NOT NULL,
  mapping_status          VARCHAR(64),
  auditable               VARCHAR(64),
  audit_method            TEXT,
  recommended_fix         TEXT,
  applicable_compliance   VARCHAR(16)
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

-- 위협 그룹 마스터
CREATE TABLE IF NOT EXISTS threat_groups (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  name  TEXT NOT NULL UNIQUE
);

-- 위협 그룹 ↔ SAGE-Threat 요구사항 매핑(다:다)
CREATE TABLE IF NOT EXISTS threat_group_map (
  group_id       INTEGER NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
  requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, requirement_id)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS ix_requirements_framework ON requirements(framework_code);
CREATE INDEX IF NOT EXISTS ix_tgm_req ON threat_group_map(requirement_id);
CREATE INDEX IF NOT EXISTS ix_tgm_group ON threat_group_map(group_id);

COMMIT;

PRAGMA foreign_keys=ON;
"""

CHECKS = [
    "PRAGMA integrity_check;",
    "PRAGMA foreign_key_check;",
    "SELECT count(*) AS n FROM requirements;",
    "PRAGMA table_info('requirements');",
    "PRAGMA table_info('threat_groups');",
    "PRAGMA table_info('threat_group_map');",
]

if __name__ == "__main__":
    engine = create_engine(DB_URL, future=True)
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.executescript(SQL)
        raw.commit()
    finally:
        raw.close()

    with engine.begin() as conn:
        for q in CHECKS:
            res = conn.exec_driver_sql(q).fetchall()
            print(q, "->", res)
