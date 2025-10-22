import csv
from pathlib import Path
from sqlalchemy.orm import Session
from app.core.db import engine, SessionLocal
from app.models import Framework, Requirement, Mapping, RequirementMapping
from app.core.db import Base


Base.metadata.create_all(bind=engine)

def upsert_framework(db: Session, code: str):
    fw = db.get(Framework, code)
    if not fw:
        fw = Framework(code=code, name=code)
        db.add(fw)
    return fw

def load_mappings(db: Session, mapping_csv: Path):
    """
    매핑 테이블 적재
    """
    with mapping_csv.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            code = (row.get("ID") or "").strip()
            if not code:
                continue
            m = db.get(Mapping, code)
            if not m:
                m = Mapping(code=code)
                db.add(m)
            m.category = (row.get("매핑번호") or "").strip()
            m.service = (row.get("서비스") or "").strip()
            m.console_path = (row.get("콘솔 위치") or "").strip()
            m.check_how = (row.get("점검/해결 방법") or "").strip()
            m.cli_cmd = (row.get("CLI 명령어") or "").strip()
            m.return_field = (row.get("리턴 필드 예시") or "").strip()
            m.compliant_value = (row.get("이행(Compliant) 값") or "").strip()
            m.non_compliant_value = (row.get("미이행(Non-Compliant) 값") or "").strip()
            m.console_fix = (row.get("콘솔 해결 방법") or "").strip()
            m.cli_fix_cmd = (row.get("CLI 해결 명령") or "").strip()
    db.commit()

def load_requirements(db: Session, req_csv: Path):
    """
    요건 CSV 적재 + 매핑 관계 테이블 구성
    """
    with req_csv.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            framework_code = (row.get("컴플라이언스") or "").strip()
            if not framework_code:
                continue
            upsert_framework(db, framework_code)

            item_code = (row.get("세부항목") or "").strip() or None
            title = item_code or (row.get("규제내용") or "")[:80]
            r = Requirement(
                framework_code=framework_code,
                item_code=item_code,
                title=title,
                description=(row.get("규제내용") or "").strip(),
                mapping_status=(row.get("매핑여부(직접매핑/해당없음)") or "").strip() or None,
                auditable=(row.get("감사가능") or "").strip() or None,
                audit_method=(row.get("감사방법(AWS 콘솔/CLI)") or "").strip() or None,
            )
            db.add(r)
            db.flush()  # r.id 확보

            # 매핑ID: "1.0-01;1.0-02" 형태 지원
            mapping_ids = (row.get("매핑ID") or "").replace(" ", "")
            if mapping_ids:
                for mc in mapping_ids.split(";"):
                    if not mc:
                        continue
                    db.add(RequirementMapping(requirement_id=r.id, mapping_code=mc, relation_type="direct"))
        db.commit()

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--requirements", type=Path, required=True, help="요건 CSV 경로")
    p.add_argument("--mappings", type=Path, required=True, help="매핑 CSV 경로")
    args = p.parse_args()

    with SessionLocal() as db:
        load_mappings(db, args.mappings)
        load_requirements(db, args.requirements)
    print("✅ CSV 적재 완료")

if __name__ == "__main__":
    main()