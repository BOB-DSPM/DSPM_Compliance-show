#!/usr/bin/env python3
# scripts/load_csv.py (improved with '권장해결(요약)', '해당컴플' support)
# - CSV/TSV 자동 구분, 인코딩 지정 가능
# - 재실행 안전(Idempotent): 기존 Framework/Mapping/Requirement/관계 중복 방지
# - 대용량 대응: 배치 커밋, bulk insert
# - 유연한 헤더 매핑(한글/공백/대소문자 차이 흡수)
# - 드라이런/부분 업데이트/요건-매핑 관계 중복 제거
# - 요약 통계 출력
# - ✅ requirements.recommended_fix / requirements.applicable_compliance 적재 지원

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Dict, Tuple, Optional, Any, Set

from sqlalchemy.orm import Session
from sqlalchemy import select
from app.core.db import engine, SessionLocal
from app.models import Framework, Requirement, Mapping, RequirementMapping
from app.core.db import Base


# =========================
# 설정/헬퍼
# =========================

def log(msg: str):
    print(f"[load_csv] {msg}")

@dataclass(frozen=True)
class HeaderSpec:
    required: List[str]
    aliases: Dict[str, List[str]]

# 요구 CSV 헤더 스펙(유연 매핑)
REQ_SPEC = HeaderSpec(
    required=["컴플라이언스", "규제내용"],
    aliases={
        "세부항목": ["세부항목", "요건코드", "항목코드", "item_code", "세부 항목"],
        "규제내용": ["규제내용", "요건내용", "설명", "description"],
        "컴플라이언스": ["컴플라이언스", "프레임워크", "framework", "framework_code", "Code"],
        "매핑여부(직접매핑/해당없음)": ["매핑여부(직접매핑/해당없음)", "매핑여부", "mapping_status"],
        "감사가능": ["감사가능", "auditable"],
        "감사방법(AWS 콘솔/CLI)": ["감사방법(AWS 콘솔/CLI)", "감사방법", "audit_method"],
        "매핑ID": ["매핑ID", "매핑코드", "mapping_ids", "mapping_id"],
        # ✅ 추가 필드
        "권장해결(요약)": [
            "권장해결(요약)", "권장해결", "해결요약", "권장 해결(요약)",
            "recommended_fix", "recommended", "remediation", "fix_summary"
        ],
        "해당컴플": [
            "해당컴플", "해당 컴플", "해당컴플라이언스",
            "applicable", "applicable_compliance", "applicable compliance"
        ],
    },
)

MAP_SPEC = HeaderSpec(
    required=["ID"],
    aliases={
        "ID": ["ID", "id", "코드", "mapping_code"],
        "매핑번호": ["매핑번호", "카테고리", "category"],
        "서비스": ["서비스", "service"],
        "콘솔 위치": ["콘솔 위치", "console_path", "console"],
        "점검/해결 방법": ["점검/해결 방법", "점검방법", "check_how", "howto"],
        "CLI 명령어": ["CLI 명령어", "cli", "cli_cmd"],
        "리턴 필드 예시": ["리턴 필드 예시", "return_field"],
        "이행(Compliant) 값": ["이행(Compliant) 값", "compliant_value"],
        "미이행(Non-Compliant) 값": ["미이행(Non-Compliant) 값", "non_compliant_value"],
        "콘솔 해결 방법": ["콘솔 해결 방법", "console_fix"],
        "CLI 해결 명령": ["CLI 해결 명령", "cli_fix_cmd"],
    },
)

def normalize_header_map(fieldnames: List[str], spec: HeaderSpec) -> Dict[str, str]:
    """
    CSV 원본 헤더(fieldnames)를 논리 키로 매핑.
    반환 dict: {논리키 -> 실제헤더}
    """
    if not fieldnames:
        return {}

    def key_norm(s: str) -> str:
        return "".join(s.strip().lower().split())

    norm_to_actual = {key_norm(h): h for h in fieldnames}
    mapping: Dict[str, str] = {}

    for logical, alist in spec.aliases.items():
        for cand in alist:
            n = key_norm(cand)
            if n in norm_to_actual:
                mapping[logical] = norm_to_actual[n]
                break

    # required 보정
    missing = []
    for r in spec.required:
        if r not in mapping:
            missing.append(r)
    if missing:
        log(f"⚠️  아래 필수 컬럼이 보이지 않습니다: {missing} (헤더: {fieldnames})")
        for r in missing[:]:
            if r in fieldnames:
                mapping[r] = r
                missing.remove(r)
    if missing:
        raise ValueError(f"필수 컬럼 매핑 실패: {missing}")

    return mapping

def getv(row: Dict[str, Any], hdrmap: Dict[str, str], logical_key: str, default: str = "") -> str:
    real = hdrmap.get(logical_key)
    if real is None:
        return default
    return (row.get(real) or "").strip()

def auto_dialect(path: Path, forced: Optional[str]) -> Dict[str, Any]:
    if forced == "csv":
        return {"delimiter": ",", "quotechar": '"'}
    if forced == "tsv":
        return {"delimiter": "\t", "quotechar": '"'}
    if path.suffix.lower() == ".tsv":
        return {"delimiter": "\t", "quotechar": '"'}
    return {"delimiter": ",", "quotechar": '"'}

def split_mapping_ids(val: str) -> List[str]:
    # "1.0-01; 1.0-02 ;" -> ["1.0-01","1.0-02"]
    parts = [p.strip() for p in val.replace(",", ";").split(";")]
    return [p for p in parts if p]

# =========================
# 업서트/로더 로직
# =========================

def upsert_framework(db: Session, code: str) -> Framework:
    fw = db.get(Framework, code)
    if not fw:
        fw = Framework(code=code, name=code)
        db.add(fw)
    return fw

def upsert_mapping(db: Session, code: str, values: Dict[str, str], merge_mode: str = "overwrite") -> Mapping:
    """
    merge_mode:
      - overwrite: 항상 덮어씀
      - fill: 빈 값일 때만 갱신
    """
    m = db.get(Mapping, code)
    if not m:
        m = Mapping(code=code)
        db.add(m)

    def assign(attr: str, newval: str):
        cur = getattr(m, attr, None) or ""
        if merge_mode == "fill":
            if not cur and newval:
                setattr(m, attr, newval)
        else:
            setattr(m, attr, newval)

    assign("category", values.get("매핑번호", ""))
    assign("service", values.get("서비스", ""))
    assign("console_path", values.get("콘솔 위치", ""))
    assign("check_how", values.get("점검/해결 방법", ""))
    assign("cli_cmd", values.get("CLI 명령어", ""))
    assign("return_field", values.get("리턴 필드 예시", ""))
    assign("compliant_value", values.get("이행(Compliant) 값", ""))
    assign("non_compliant_value", values.get("미이행(Non-Compliant) 값", ""))
    assign("console_fix", values.get("콘솔 해결 방법", ""))
    assign("cli_fix_cmd", values.get("CLI 해결 명령", ""))

    return m

def find_existing_requirement(db: Session, framework_code: str, item_code: Optional[str], title: str) -> Optional[Requirement]:
    """
    재실행 시 중복 생기지 않도록 요건을 유일키로 탐색.
    우선순위:
      1) (framework_code, item_code) 둘 다 있는 경우
      2) (framework_code, title) 로 fallback
    """
    if item_code:
        q = db.execute(
            select(Requirement).where(
                Requirement.framework_code == framework_code,
                Requirement.item_code == item_code
            )
        ).scalars().first()
        if q:
            return q
    q = db.execute(
        select(Requirement).where(
            Requirement.framework_code == framework_code,
            Requirement.title == title
        )
    ).scalars().first()
    return q

def upsert_requirement(
    db: Session,
    framework_code: str,
    item_code: Optional[str],
    title: str,
    description: str,
    mapping_status: Optional[str],
    auditable: Optional[str],
    audit_method: Optional[str],
    recommended_fix: Optional[str],
    applicable_compliance: Optional[str],
    merge_mode: str = "overwrite",
) -> Requirement:
    r = find_existing_requirement(db, framework_code, item_code, title)
    if not r:
        r = Requirement(
            framework_code=framework_code,
            item_code=item_code,
            title=title,
            description=description,
            mapping_status=mapping_status,
            auditable=auditable,
            audit_method=audit_method,
            recommended_fix=(recommended_fix or None),
            applicable_compliance=(applicable_compliance or None),
        )
        db.add(r)
        db.flush()  # r.id 확보
        return r

    def assign(attr: str, newval: Optional[str]):
        cur = getattr(r, attr, None)
        nv = (newval or "").strip() or None
        if merge_mode == "fill":
            if (cur is None or str(cur).strip() == "") and nv:
                setattr(r, attr, nv)
        else:
            setattr(r, attr, nv)

    assign("item_code", item_code)
    assign("title", title)
    assign("description", description)
    assign("mapping_status", mapping_status)
    assign("auditable", auditable)
    assign("audit_method", audit_method)
    # ✅ 추가 필드
    assign("recommended_fix", recommended_fix)
    assign("applicable_compliance", applicable_compliance)
    return r

def attach_requirement_mappings(
    db: Session,
    requirement_id: int,
    mapping_codes: Iterable[str],
    relation_type: str = "direct",
):
    if not mapping_codes:
        return 0

    existing: Set[str] = set(
        db.execute(
            select(RequirementMapping.mapping_code)
            .where(RequirementMapping.requirement_id == requirement_id)
        ).scalars().all()
    )

    news = []
    for code in mapping_codes:
        if code in existing:
            continue
        news.append(RequirementMapping(
            requirement_id=requirement_id,
            mapping_code=code,
            relation_type=relation_type
        ))

    if news:
        db.bulk_save_objects(news)
    return len(news)

# =========================
# CSV 로더
# =========================

def load_mappings(db: Session, mapping_csv: Path, dialect: Dict[str, Any], encoding: str, merge_mode: str):
    with mapping_csv.open("r", encoding=encoding, newline="") as f:
        reader = csv.DictReader(f, **dialect)
        hdrmap = normalize_header_map(reader.fieldnames or [], MAP_SPEC)

        total, created = 0, 0
        for row in reader:
            total += 1
            code = getv(row, hdrmap, "ID")
            if not code:
                continue
            values = {k: getv(row, hdrmap, k) for k in MAP_SPEC.aliases.keys()}
            existed = bool(db.get(Mapping, code))
            upsert_mapping(db, code, values, merge_mode=merge_mode)
            if not existed:
                created += 1

        log(f"Mappings: total={total}, created={created}, updated={total - created}")

def load_requirements(db: Session, req_csv: Path, dialect: Dict[str, Any], encoding: str, merge_mode: str):
    with req_csv.open("r", encoding=encoding, newline="") as f:
        reader = csv.DictReader(f, **dialect)
        hdrmap = normalize_header_map(reader.fieldnames or [], REQ_SPEC)

        total_req, created_req, linked_rel = 0, 0, 0

        for row in reader:
            framework_code = getv(row, hdrmap, "컴플라이언스")
            if not framework_code:
                continue
            total_req += 1

            upsert_framework(db, framework_code)

            item_code = getv(row, hdrmap, "세부항목") or None
            description = getv(row, hdrmap, "규제내용")
            title = item_code or (description[:80] if description else "요건")
            mapping_status = getv(row, hdrmap, "매핑여부(직접매핑/해당없음)") or None
            auditable = getv(row, hdrmap, "감사가능") or None
            audit_method = getv(row, hdrmap, "감사방법(AWS 콘솔/CLI)") or None
            # ✅ 추가 필드 추출
            recommended_fix = getv(row, hdrmap, "권장해결(요약)") or None
            applicable_compliance = getv(row, hdrmap, "해당컴플") or None

            existed = bool(find_existing_requirement(db, framework_code, item_code, title))
            r = upsert_requirement(
                db, framework_code, item_code, title, description,
                mapping_status, auditable, audit_method,
                recommended_fix, applicable_compliance,
                merge_mode=merge_mode
            )
            if not existed:
                created_req += 1

            # 관계(매핑ID)
            mapping_ids = split_mapping_ids(getv(row, hdrmap, "매핑ID"))
            if mapping_ids:
                linked_rel += attach_requirement_mappings(db, r.id, mapping_ids, relation_type="direct")

        log(f"Requirements: total={total_req}, created={created_req}, updated={total_req - created_req}, links_added={linked_rel}")

# =========================
# 메인
# =========================

def main():
    parser = argparse.ArgumentParser(description="CSV → SQLite(Postgres도 OK) 로더 (재실행 안전/자동 매핑)")
    parser.add_argument("--requirements", type=Path, required=True, help="요건 CSV/TSV 경로")
    parser.add_argument("--mappings", type=Path, required=True, help="매핑 CSV/TSV 경로")
    parser.add_argument("--encoding", default="utf-8-sig", help="입력 파일 인코딩 (기본: utf-8-sig)")
    parser.add_argument("--format", choices=["auto", "csv", "tsv"], default="auto", help="파일 포맷 강제 (기본: auto)")
    parser.add_argument("--merge-mode", choices=["overwrite", "fill"], default="overwrite",
                        help="overwrite=항상 덮어씀, fill=기존값이 빈 칸일 때만 채움")
    parser.add_argument("--commit-every", type=int, default=5000, help="N행마다 커밋 (대용량 안정성)")
    parser.add_argument("--dry-run", action="store_true", help="DB 변경 없이 파싱만 수행")
    args = parser.parse_args()

    # DB & 테이블 생성
    Base.metadata.create_all(bind=engine)

    # 파일 포맷/인코딩
    req_dialect = auto_dialect(args.requirements, None if args.format == "auto" else args.format)
    map_dialect = auto_dialect(args.mappings, None if args.format == "auto" else args.format)

    log(f"requirements: {args.requirements} ({args.encoding}, {req_dialect})")
    log(f"mappings:     {args.mappings} ({args.encoding}, {map_dialect})")
    log(f"merge_mode={args.merge_mode}, dry_run={args.dry_run}")

    if args.dry_run:
        with args.mappings.open("r", encoding=args.encoding, newline="") as f:
            reader = csv.DictReader(f, **map_dialect)
            _ = normalize_header_map(reader.fieldnames or [], MAP_SPEC)
        with args.requirements.open("r", encoding=args.encoding, newline="") as f:
            reader = csv.DictReader(f, **req_dialect)
            _ = normalize_header_map(reader.fieldnames or [], REQ_SPEC)
        log("DRY-RUN OK (헤더 매핑 검증 완료)")
        return

    with SessionLocal() as db:
        # 1) 매핑 선적재
        load_mappings(db, args.mappings, map_dialect, args.encoding, merge_mode=args.merge_mode)
        db.commit()

        # 2) 요건+관계 (+권장해결/해당컴플)
        load_requirements(db, args.requirements, req_dialect, args.encoding, merge_mode=args.merge_mode)
        db.commit()

    log("✅ CSV 적재 완료")

if __name__ == "__main__":
    main()
