# app/services/compliance_service.py
from __future__ import annotations
from typing import List, Optional
import re
from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session
from ..models import Framework, Requirement, Mapping, RequirementMapping
from ..schemas import (
    FrameworkCountOut,
    RequirementRowOut,
    MappingOut,
    RequirementDetailOut,
    RequirementMiniOut,
    ApplicableComplianceHitOut,
)

def ensure_tables(engine) -> None:
    from ..core.db import Base
    Base.metadata.create_all(bind=engine)

def framework_counts(db: Session) -> List[FrameworkCountOut]:
    rows = db.execute(
        select(Requirement.framework_code, func.count(Requirement.id))
        .group_by(Requirement.framework_code)
        .order_by(Requirement.framework_code)
    ).all()
    return [FrameworkCountOut(framework=f, count=c) for (f, c) in rows]

def _extract_regulation_text(req: Requirement) -> Optional[str]:
    for field in ("regulation", "reg_text", "description", "content", "detail", "body"):
        if hasattr(req, field):
            val = getattr(req, field)
            if val:
                return str(val)
    return None

# --- SAGE-Threat 전용: applicable_compliance 파싱 & 재조회 ---
_CODE_TITLE_RE = re.compile(r"^\s*([0-9][\d\.]*)\s*(.*)$")

def _split_tokens(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(";") if t.strip()]

def _parse_code_title(token: str) -> tuple[Optional[str], Optional[str]]:
    m = _CODE_TITLE_RE.match(token)
    if not m:
        return None, token.strip() or None
    code = (m.group(1) or "").strip() or None
    title = (m.group(2) or "").strip() or None
    return code, title

def _mini_from_row(r: Requirement) -> RequirementMiniOut:
    return RequirementMiniOut(
        id=r.id,
        framework_code=r.framework_code,
        item_code=r.item_code,
        title=r.title,
        regulation=_extract_regulation_text(r) or getattr(r, "description", None),
    )

def _query_matches_for_token(db: Session, code: Optional[str], title: Optional[str]) -> List[RequirementMiniOut]:
    q = db.query(Requirement).filter(Requirement.framework_code != "SAGE-Threat")
    conds = []
    if code:
        conds.append(Requirement.item_code == code)
    if title:
        conds.append(Requirement.title.ilike(f"%{title}%"))
    if not conds:
        return []
    rows = q.filter(or_(*conds)).order_by(Requirement.framework_code, Requirement.id).all()
    return [_mini_from_row(r) for r in rows]

def _build_applicable_hits(db: Session, applicable_compliance: Optional[str]) -> List[ApplicableComplianceHitOut]:
    hits: List[ApplicableComplianceHitOut] = []
    for token in _split_tokens(applicable_compliance):
        code, title = _parse_code_title(token)
        matches = _query_matches_for_token(db, code, title)
        hits.append(ApplicableComplianceHitOut(raw=token, code=code, title=title, matches=matches))
    return hits

# ✅ 역방향(컴플라이언스 → 위협들): DB 수정 없이 문자열 검색만
def _find_threats_for_requirement(db: Session, item_code: Optional[str], title: Optional[str]) -> List[RequirementMiniOut]:
    """
    - SAGE-Threat.applicable_compliance 내에 컴플라이언스의 item_code 또는 title 조각이 포함되어 있으면 히트
    - DB/스키마 변경 없이 ILIKE %%검색%% 만 사용
    """
    conds = []
    if item_code:
        conds.append(Requirement.applicable_compliance.ilike(f"%{item_code}%"))
    if title:
        # 너무 긴 제목은 일부만; 간단 키워드 매칭
        key = title.strip()
        if len(key) > 64:
            key = key[:64]
        conds.append(Requirement.applicable_compliance.ilike(f"%{key}%"))

    if not conds:
        return []

    rows = (
        db.query(Requirement)
        .filter(Requirement.framework_code == "SAGE-Threat")
        .filter(or_(*conds))
        .order_by(Requirement.id)
        .all()
    )
    return [_mini_from_row(r) for r in rows]

def list_requirements(db: Session, framework_code: str) -> List[RequirementRowOut]:
    rows = (
        db.query(
            Requirement.id.label("id"),
            Requirement.item_code.label("item_code"),
            Requirement.title.label("title"),
            Requirement.mapping_status.label("mapping_status"),
            Requirement.description.label("regulation"),
            Requirement.auditable.label("auditable"),
            Requirement.audit_method.label("audit_method"),
            Requirement.recommended_fix.label("recommended_fix"),
            Requirement.applicable_compliance.label("applicable_compliance"),
        )
        .filter(Requirement.framework_code == framework_code)
        .order_by(Requirement.id)
        .all()
    )
    models = [RequirementRowOut.model_validate(dict(r._mapping)) for r in rows]

    if framework_code == "SAGE-Threat":
        # 정방향(위협 → 컴플라이언스)
        enriched: List[RequirementRowOut] = []
        for m in models:
            hits = _build_applicable_hits(db, m.applicable_compliance)
            enriched.append(m.model_copy(update={"applicable_hits": hits}))
        return enriched

    # ✅ 역방향(컴플라이언스 → 위협)
    enriched: List[RequirementRowOut] = []
    for m in models:
        th = _find_threats_for_requirement(db, m.item_code, m.title)
        enriched.append(m.model_copy(update={"threat_hits": th}))
    return enriched

def requirement_detail(db: Session, code: str, req_id: int) -> Optional[RequirementDetailOut]:
    req = (
        db.query(Requirement)
        .filter(Requirement.framework_code == code, Requirement.id == req_id)
        .first()
    )
    if not req:
        return None

    maps = (
        db.query(Mapping)
        .join(RequirementMapping, RequirementMapping.mapping_code == Mapping.code)
        .filter(RequirementMapping.requirement_id == req.id)
        .all()
    )

    req_out = RequirementRowOut.model_validate(req)

    if code == "SAGE-Threat":
        # 정방향
        hits = _build_applicable_hits(db, getattr(req, "applicable_compliance", None))
        req_out = req_out.model_copy(update={"applicable_hits": hits})
    else:
        # ✅ 역방향(컴플라이언스 → 위협)
        th = _find_threats_for_requirement(db, req.item_code, req.title)
        req_out = req_out.model_copy(update={"threat_hits": th})

    return RequirementDetailOut(
        framework=req.framework_code,
        regulation=_extract_regulation_text(req),
        requirement=req_out,
        mappings=[MappingOut.model_validate(m) for m in maps],
    )
