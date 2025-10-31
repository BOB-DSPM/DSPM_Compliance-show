# app/routers/compliance.py
from __future__ import annotations
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..core.db import get_db, engine
from ..services.compliance_service import (
    ensure_tables,
    framework_counts,
    # 그룹 주입 버전이 필요하면 아래 두 개도 계속 사용 가능
    list_requirements_with_groups,
    requirement_detail_with_groups,
    # (신규) 위협 결합 버전
    list_requirements_with_threats,
    requirement_detail_with_threats,
)
from ..schemas import (
    FrameworkCountOut,
    RequirementRowWithGroupsOut,
    RequirementDetailWithGroupsOut,
    RequirementRowWithThreatsOut,
    RequirementDetailWithThreatsOut,
)
from ..utils.etag import etag_response

ensure_tables(engine)
router = APIRouter(tags=["compliance"])

@router.get("/stats", response_model=List[FrameworkCountOut])
def get_counts(request: Request, response: Response, db: Session = Depends(get_db)):
    data = framework_counts(db)
    return etag_response(request, response, [d.model_dump() for d in data])

# -----------------------------
# (A) 기존: 그룹 주입 버전(호환)
# -----------------------------
@router.get("/{code}/requirements:groups", response_model=List[RequirementRowWithGroupsOut])
def get_requirements_with_groups(code: str, request: Request, response: Response, db: Session = Depends(get_db)):
    rows = list_requirements_with_groups(db, code)
    if not rows:
        raise HTTPException(status_code=404, detail="Framework not found or no requirements")
    response.headers["X-Handler"] = "list_requirements_with_groups"
    return etag_response(request, response, [r.model_dump() for r in rows])

@router.get("/{code}/requirements/{req_id}/mappings:groups", response_model=RequirementDetailWithGroupsOut)
def get_requirement_mapping_with_groups(code: str, req_id: int, request: Request, response: Response, db: Session = Depends(get_db)):
    detail = requirement_detail_with_groups(db, code, req_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Requirement not found")
    response.headers["X-Handler"] = "requirement_detail_with_groups"
    return etag_response(request, response, detail.model_dump())

# -----------------------------
# (B) 신규: 위협 결합 버전 (기본 엔드포인트로 사용 권장)
# -----------------------------
@router.get("/{code}/requirements", response_model=List[RequirementRowWithThreatsOut])
def get_requirements_with_threats(code: str, request: Request, response: Response, db: Session = Depends(get_db)):
    rows = list_requirements_with_threats(db, code)
    if not rows:
        raise HTTPException(status_code=404, detail="Framework not found or no requirements")
    response.headers["X-Handler"] = "list_requirements_with_threats"
    return etag_response(request, response, [r.model_dump() for r in rows])

@router.get("/{code}/requirements/{req_id}/mappings", response_model=RequirementDetailWithThreatsOut)
def get_requirement_mapping_with_threats(code: str, req_id: int, request: Request, response: Response, db: Session = Depends(get_db)):
    detail = requirement_detail_with_threats(db, code, req_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Requirement not found")
    response.headers["X-Handler"] = "requirement_detail_with_threats"
    return etag_response(request, response, detail.model_dump())
