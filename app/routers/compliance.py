# app/routers/compliance.py
from __future__ import annotations
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

# ✅ 여기만 바꿔주세요: session → db
from ..core.db import get_db, engine

from ..services.compliance_service import (
    ensure_tables,
    framework_counts,
    list_requirements_with_groups,
    requirement_detail_with_groups,
)

from ..schemas import (
    FrameworkCountOut,
    RequirementRowWithGroupsOut,
    RequirementDetailWithGroupsOut,
)

from ..utils.etag import etag_response

ensure_tables(engine)
router = APIRouter(prefix="/compliance", tags=["compliance"])

@router.get("/stats", response_model=List[FrameworkCountOut])
def get_counts(request: Request, response: Response, db: Session = Depends(get_db)):
    data = framework_counts(db)
    return etag_response(request, response, [d.model_dump() for d in data])

@router.get("/{code}/requirements", response_model=List[RequirementRowWithGroupsOut])
def get_requirements(code: str, request: Request, response: Response, db: Session = Depends(get_db)):
    rows = list_requirements_with_groups(db, code)
    if not rows:
        raise HTTPException(status_code=404, detail="Framework not found or no requirements")
    response.headers["X-Handler"] = "list_requirements_with_groups"  # (선택) 디버그용
    return etag_response(request, response, [r.model_dump() for r in rows])

@router.get("/{code}/requirements/{req_id}/mappings", response_model=RequirementDetailWithGroupsOut)
def get_requirement_mapping(code: str, req_id: int, request: Request, response: Response, db: Session = Depends(get_db)):
    detail = requirement_detail_with_groups(db, code, req_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Requirement not found")
    response.headers["X-Handler"] = "requirement_detail_with_groups"  # (선택) 디버그용
    return etag_response(request, response, detail.model_dump())
