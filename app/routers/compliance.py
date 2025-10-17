# app/routers/compliance.py
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from ..core.db import get_db, engine
from ..services.compliance_service import (
    framework_counts, list_requirements, requirement_detail, ensure_tables
)
from ..schemas import FrameworkCountOut, RequirementRowOut, RequirementDetailOut
from ..utils.etag import etag_response   # ✅ 추가

ensure_tables(engine)
router = APIRouter(tags=["compliance"])

@router.get("/stats", response_model=list[FrameworkCountOut])
def get_counts(request: Request, response: Response, db: Session = Depends(get_db)):
    data = framework_counts(db)
    return etag_response(request, response, [d.model_dump() for d in data])

@router.get("/{code}/requirements", response_model=list[RequirementRowOut])
def get_requirements(code: str, request: Request, response: Response, db: Session = Depends(get_db)):
    rows = list_requirements(db, code)
    if not rows:
        raise HTTPException(status_code=404, detail="Framework not found or no requirements")
    # Pydantic 모델을 dict로 변환해서 직렬화 안정성 확보
    return etag_response(request, response, [r.model_dump() for r in rows])

@router.get("/{code}/requirements/{req_id}/mappings", response_model=RequirementDetailOut)
def get_requirement_mapping(code: str, req_id: int, request: Request, response: Response, db: Session = Depends(get_db)):
    detail = requirement_detail(db, code, req_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Requirement not found")
    return etag_response(request, response, detail.model_dump())
