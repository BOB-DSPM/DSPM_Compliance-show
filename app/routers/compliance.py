from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..core.db import get_db, engine
from ..services.compliance_service import (
    framework_counts, list_requirements, requirement_detail, ensure_tables
)
from ..schemas import FrameworkCountOut, RequirementRowOut, RequirementDetailOut
ensure_tables(engine)

router = APIRouter(tags=["compliance"])

# 2) 컴플라이언스별 항목 개수
@router.get("/stats", response_model=list[FrameworkCountOut])
def get_counts(db: Session = Depends(get_db)):
    return framework_counts(db)

# 3) 특정 컴플라이언스의 항목 목록
@router.get("/{code}/requirements", response_model=list[RequirementRowOut])
def get_requirements(code: str, db: Session = Depends(get_db)):
    rows = list_requirements(db, code)
    if not rows:
        raise HTTPException(status_code=404, detail="Framework not found or no requirements")
    return rows

# 4) 특정 항목의 매핑(감사/해결)
@router.get("/{code}/requirements/{req_id}/mappings", response_model=RequirementDetailOut)
def get_requirement_mapping(code: str, req_id: int, db: Session = Depends(get_db)):
    detail = requirement_detail(db, code, req_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Requirement not found")
    return detail
