# app/services/compliance_service.py
from __future__ import annotations
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import Framework, Requirement, Mapping
from ..schemas import FrameworkCountOut, RequirementRowOut, MappingOut, RequirementDetailOut

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

def list_requirements(db: Session, framework_code: str):
    rows = (
        db.query(
            Requirement.id,
            Requirement.item_code,
            Requirement.title,
            Requirement.mapping_status,
            Requirement.description.label("regulation"),
            Requirement.auditable,
            Requirement.audit_method,
            Requirement.recommended_fix,          # ✅ 추가
            Requirement.applicable_compliance,     # ✅ 추가
        )
        .filter(Requirement.framework_code == framework_code)
        .order_by(Requirement.id)
        .all()
    )
    return [RequirementRowOut.model_validate(r) for r in rows]

def requirement_detail(db: Session, code: str, req_id: int) -> Optional[RequirementDetailOut]:
    req = db.get(Requirement, req_id)
    if not req or req.framework_code != code:
        return None

    maps = [
        MappingOut(
            code=m.code,
            category=m.category,
            service=m.service,
            console_path=m.console_path,
            check_how=m.check_how,
            cli_cmd=m.cli_cmd,
            return_field=m.return_field,
            compliant_value=m.compliant_value,
            non_compliant_value=m.non_compliant_value,
            console_fix=m.console_fix,
            cli_fix_cmd=m.cli_fix_cmd,
        )
        for m in req.mappings
    ]

    return RequirementDetailOut(
        framework=req.framework_code,
        requirement=RequirementRowOut(
            id=req.id,
            item_code=req.item_code,
            title=req.title,
            mapping_status=req.mapping_status,
            regulation=_extract_regulation_text(req),  # ✅ 디테일에서도 동일 소스
        ),
        regulation=_extract_regulation_text(req),  # (호환용 필드 유지)
        mappings=maps,
    )
