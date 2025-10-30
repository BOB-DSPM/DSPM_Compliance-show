# app/services/compliance_service.py
from __future__ import annotations

import re
from typing import List, Optional

from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session

from ..models import (
    Framework,
    Requirement,
    Mapping,
    RequirementMapping,
    ThreatGroup,
    Threat,
)
from ..schemas import (
    FrameworkCountOut,
    RequirementRowOut,
    MappingOut,
    RequirementDetailOut,
    RequirementMiniOut,
    ApplicableComplianceHitOut,
    RequirementRowWithGroupsOut,
    RequirementDetailWithGroupsOut,
)

def ensure_tables(engine) -> None:
    from ..core.db import Base
    Base.metadata.create_all(bind=engine)

def _extract_regulation_text(req: Requirement) -> Optional[str]:
    for field in ("regulation", "reg_text", "description", "content", "detail", "body"):
        if hasattr(req, field):
            val = getattr(req, field)
            if val:
                return str(val)
    return None

def framework_counts(db: Session) -> List[FrameworkCountOut]:
    rows = (
        db.execute(
            select(Requirement.framework_code, func.count(Requirement.id))
            .group_by(Requirement.framework_code)
            .order_by(Requirement.framework_code)
        )
        .all()
    )
    return [FrameworkCountOut(framework=f, count=c) for (f, c) in rows]

# -----------------------------
# applicable_compliance 파싱/재조회
# -----------------------------
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
    out: List[RequirementMiniOut] = []
    for r in rows:
        out.append(
            RequirementMiniOut(
                id=r.id,
                framework_code=r.framework_code,
                item_code=r.item_code,
                title=r.title,
                regulation=_extract_regulation_text(r) or getattr(r, "description", None),
            )
        )
    return out

def _build_applicable_hits(db: Session, applicable_compliance: Optional[str]) -> List[ApplicableComplianceHitOut]:
    hits: List[ApplicableComplianceHitOut] = []
    for token in _split_tokens(applicable_compliance):
        code, title = _parse_code_title(token)
        matches = _query_matches_for_token(db, code, title)
        hits.append(ApplicableComplianceHitOut(raw=token, code=code, title=title, matches=matches))
    return hits

# -----------------------------
# 기본 목록/상세
# -----------------------------
def list_requirements(db: Session, framework_code: str) -> List[RequirementRowOut]:
    """
    목록 API에서 각 항목별 매핑 코드들을 함께 반환한다.
    - SQLite: group_concat 사용
    - 다른 DB 사용 시 string_agg로 교체 필요
    """
    mapping_codes_csv = func.group_concat(RequirementMapping.mapping_code, ";")

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
            mapping_codes_csv.label("mapping_codes_csv"),
        )
        .outerjoin(
            RequirementMapping,
            RequirementMapping.requirement_id == Requirement.id,
        )
        .filter(Requirement.framework_code == framework_code)
        .group_by(
            Requirement.id,
            Requirement.item_code,
            Requirement.title,
            Requirement.mapping_status,
            Requirement.description,
            Requirement.auditable,
            Requirement.audit_method,
            Requirement.recommended_fix,
            Requirement.applicable_compliance,
        )
        .order_by(Requirement.id)
        .all()
    )

    models: List[RequirementRowOut] = []
    for r in rows:
        d = dict(r._mapping)
        # 정규화된 regulation 주입(모델에 따라 필드명이 달라질 수 있어 보정)
        if d.get("regulation") is None:
            # 필요 시 개별 객체 조회 없이 문자열만 보정
            pass
        # CSV -> List[str]
        csv_val = (d.pop("mapping_codes_csv", None) or "").strip()
        codes = [c for c in (csv_val.split(";") if csv_val else []) if c]
        d["mapping_codes"] = codes or None
        models.append(RequirementRowOut.model_validate(d))

    if framework_code == "SAGE-Threat":
        enriched: List[RequirementRowOut] = []
        for m in models:
            hits = _build_applicable_hits(db, m.applicable_compliance)
            enriched.append(m.model_copy(update={"applicable_hits": hits}))
        return enriched
    return models

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

    reg_text = _extract_regulation_text(req)
    # ✅ 상세에도 mapping_codes를 일관되게 제공
    mapping_codes = [m.code for m in maps]

    req_out = RequirementRowOut.model_validate(req).model_copy(
        update={
            "regulation": reg_text,
            "mapping_codes": mapping_codes or None,
        }
    )

    if code == "SAGE-Threat":
        hits = _build_applicable_hits(db, getattr(req, "applicable_compliance", None))
        req_out = req_out.model_copy(update={"applicable_hits": hits})

    return RequirementDetailOut(
        framework=req.framework_code,
        regulation=reg_text,
        requirement=req_out,
        mappings=[MappingOut.model_validate(m) for m in maps],
    )

# -----------------------------
# ThreatGroup 매핑(그룹명 추가)
# -----------------------------
def _norm_text(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _candidate_groups(db: Session, title: Optional[str]) -> List[str]:
    """
    title로 ThreatGroup 후보 전부 수집(정확→부분). 중복 제거, 원문 표기 유지.
    """
    t = _norm_text(title)
    if not t:
        return []
    names: List[str] = []

    exact = (
        db.query(ThreatGroup.name)
        .join(Threat, Threat.group_id == ThreatGroup.id)
        .filter(func.lower(Threat.title) == t)
        .distinct()
        .all()
    )
    names.extend([n for (n,) in exact])
    if names:
        return sorted(set(names))  # 정확 일치 우선

    like_hits = (
        db.query(ThreatGroup.name)
        .join(Threat, Threat.group_id == ThreatGroup.id)
        .filter(Threat.title.ilike(f"%{title}%"))
        .distinct()
        .all()
    )
    names.extend([n for (n,) in like_hits])
    return sorted(set(names))

def _pick_primary_group(candidates: List[str]) -> Optional[str]:
    return candidates[0] if candidates else None

def list_requirements_with_groups(db: Session, framework_code: str) -> List[RequirementRowWithGroupsOut]:
    """
    기존 list_requirements 결과에 threat_group(단수) + threat_groups(복수) 주입.
    SAGE-Threat가 아니면 둘 다 None.
    """
    base_rows = list_requirements(db, framework_code)
    out: List[RequirementRowWithGroupsOut] = []
    is_threat = (framework_code == "SAGE-Threat")

    for m in base_rows:
        if is_threat:
            candidates = _candidate_groups(db, m.title)
            primary = _pick_primary_group(candidates)
            out.append(
                RequirementRowWithGroupsOut.model_validate(
                    m.model_dump() | {"threat_group": primary, "threat_groups": candidates or None}
                )
            )
        else:
            out.append(
                RequirementRowWithGroupsOut.model_validate(
                    m.model_dump() | {"threat_group": None, "threat_groups": None}
                )
            )
    return out

def requirement_detail_with_groups(db: Session, code: str, req_id: int) -> Optional[RequirementDetailWithGroupsOut]:
    base = requirement_detail(db, code, req_id)
    if not base:
        return None

    if code == "SAGE-Threat":
        candidates = _candidate_groups(db, base.requirement.title)
        primary = _pick_primary_group(candidates)
        req_with_groups = RequirementRowWithGroupsOut.model_validate(
            base.requirement.model_dump() | {"threat_group": primary, "threat_groups": candidates or None}
        )
    else:
        req_with_groups = RequirementRowWithGroupsOut.model_validate(
            base.requirement.model_dump() | {"threat_group": None, "threat_groups": None}
        )

    return RequirementDetailWithGroupsOut(
        framework=base.framework,
        regulation=base.regulation,
        requirement=req_with_groups,
        mappings=base.mappings,
    )
