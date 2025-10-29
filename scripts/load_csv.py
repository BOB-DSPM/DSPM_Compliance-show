# scripts/load_threat_groups.py
#!/usr/bin/env python3
from __future__ import annotations
import csv, sys, sqlite3, pathlib

DB = "./app.db"
CSV_FILE = sys.argv[1] if len(sys.argv) > 1 else "./threat_groups.csv"

def get_or_create_group(cur, name: str) -> int:
    cur.execute("SELECT id FROM threat_groups WHERE name = ?", (name,))
    r = cur.fetchone()
    if r:
        return r[0]
    cur.execute("INSERT INTO threat_groups(name) VALUES(?)", (name,))
    return cur.lastrowid

def find_req_ids(cur, title: str) -> list[int]:
    # 1) 정확히 일치
    cur.execute("""
        SELECT id FROM requirements
        WHERE framework_code='SAGE-Threat' AND title = ?
    """, (title,))
    ids = [x[0] for x in cur.fetchall()]
    if ids:
        return ids
    # 2) LIKE
    cur.execute("""
        SELECT id FROM requirements
        WHERE framework_code='SAGE-Threat' AND title LIKE ?
    """, (f"%{title}%",))
    ids = [x[0] for x in cur.fetchall()]
    if ids:
        return ids
    # 3) description까지 (옵션)
    cur.execute("""
        SELECT id FROM requirements
        WHERE framework_code='SAGE-Threat' AND description LIKE ?
    """, (f"%{title}%",))
    return [x[0] for x in cur.fetchall()]

def main():
    if not pathlib.Path(DB).exists():
        print(f"[ERR] DB not found: {DB}")
        sys.exit(1)
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    # 스키마 보장
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS threat_groups (
      id    INTEGER PRIMARY KEY AUTOINCREMENT,
      name  TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS threat_group_map (
      group_id       INTEGER NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
      requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
      PRIMARY KEY (group_id, requirement_id)
    );
    """)

    with open(CSV_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert "위협 그룹" in reader.fieldnames and "위협" in reader.fieldnames, \
            "CSV 헤더는 '위협 그룹,위협' 이어야 합니다."
        for row in reader:
            group = row["위협 그룹"].strip()
            threats = [t.strip() for t in row["위협"].split(";") if t.strip()]
            if not group or not threats:
                continue
            gid = get_or_create_group(cur, group)
            for t in threats:
                ids = find_req_ids(cur, t)
                if not ids:
                    print(f"[WARN] 매칭 실패: 그룹='{group}', 위협제목='{t}'")
                    continue
                for rid in ids:
                    cur.execute("""
                        INSERT OR IGNORE INTO threat_group_map(group_id, requirement_id)
                        VALUES (?, ?)
                    """, (gid, rid))
    conn.commit()
    print("[OK] threat_groups / threat_group_map 로드 완료")
    # 간단 검증
    cur.execute("SELECT count(*) FROM threat_groups")
    print("groups:", cur.fetchone()[0])
    cur.execute("SELECT count(*) FROM threat_group_map")
    print("maps  :", cur.fetchone()[0])

if __name__ == "__main__":
    main()
