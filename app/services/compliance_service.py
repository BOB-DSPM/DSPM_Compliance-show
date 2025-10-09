from __future__ import annotations
from typing import List
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

def list_requirements(db: Session, code: str) -> List[RequirementRowOut]:
    fw = db.get(Framework, code)
    if not fw:
        return []
    reqs = db.execute(
        select(Requirement).where(Requirement.framework_code == code).order_by(Requirement.id)
    ).scalars().all()
    return [RequirementRowOut(id=r.id, item_code=r.item_code, title=r.title, mapping_status=r.mapping_status) for r in reqs]

def requirement_detail(db: Session, code: str, req_id: int) -> RequirementDetailOut | None:
    req = db.get(Requirement, req_id)
    if not req or req.framework_code != code:
        return None
    maps = []
    for m in req.mappings:
        maps.append(MappingOut(
            code=m.code, category=m.category, service=m.service,
            console_path=m.console_path, check_how=m.check_how, cli_cmd=m.cli_cmd,
            return_field=m.return_field, compliant_value=m.compliant_value,
            non_compliant_value=m.non_compliant_value, console_fix=m.console_fix, cli_fix_cmd=m.cli_fix_cmd
        ))
    return RequirementDetailOut(
        framework=req.framework_code,
        requirement=RequirementRowOut(id=req.id, item_code=req.item_code, title=req.title, mapping_status=req.mapping_status),
        mappings=maps
    )
