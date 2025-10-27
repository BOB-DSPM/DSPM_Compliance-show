# app/services/compliance_service.py
from __future__ import annotations
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import Framework, Requirement, Mapping, RequirementMapping
from ..schemas import (
    FrameworkCountOut,
    RequirementRowOut,
    MappingOut,
    RequirementDetailOut,
)

def ensure_tables(engine) -> None:
    """로컬/테스트 환경에서 스키마 자동 생성(운영은 마이그레이션 권장)."""
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
    """
    모델 필드명이 레포마다 다를 수 있어 안전하게 추출:
    regulation / reg_text / description / content / detail / body 순으로 탐색.
    """
    for field in ("regulation", "reg_text", "description", "content", "detail", "body"):
        if hasattr(req, field):
            val = getattr(req, field)
            if val:
                return str(val)
    return None


def list_requirements(db: Session, framework_code: str) -> List[RequirementRowOut]:
    """
    목록은 SELECT 컬럼 지정 + Row → dict(_mapping) → model_validate()로 구성.
    (Pydantic v2는 Row 자체는 못 파싱하므로 dict 변환 필요)
    """
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
    return [RequirementRowOut.model_validate(dict(r._mapping)) for r in rows]


def requirement_detail(db: Session, code: str, req_id: int) -> Optional[RequirementDetailOut]:
    """
    디테일은 ORM 객체를 그대로 Pydantic에 넘깁니다(from_attributes=True).
    """
    req = (
        db.query(Requirement)
        .filter(Requirement.framework_code == code, Requirement.id == req_id)
        .first()
    )
    if not req:
        return None

    # 매핑들 조회 (중간 테이블 통해 연결)
    maps = (
        db.query(Mapping)
        .join(RequirementMapping, RequirementMapping.mapping_code == Mapping.code)
        .filter(RequirementMapping.requirement_id == req.id)
        .all()
    )

    return RequirementDetailOut(
        framework=req.framework_code,
        regulation=_extract_regulation_text(req),  # (호환용 필드)
        requirement=RequirementRowOut.model_validate(req),
        mappings=[MappingOut.model_validate(m) for m in maps],
    )
