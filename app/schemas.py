# app/schemas.py
from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

FROM_ATTRS = ConfigDict(from_attributes=True)

class FrameworkCountOut(BaseModel):
    framework: str
    count: int
    model_config = FROM_ATTRS

class RequirementMiniOut(BaseModel):
    id: int
    framework_code: str
    item_code: Optional[str] = None
    title: str
    regulation: Optional[str] = None
    model_config = FROM_ATTRS

class ApplicableComplianceHitOut(BaseModel):
    raw: str                          # 원본 토큰 (“7.4.3 Accuracy and quality”)
    code: Optional[str] = None        # 파싱된 코드 (“7.4.3”)
    title: Optional[str] = None       # 파싱된 제목 (“Accuracy and quality”)
    matches: List[RequirementMiniOut] = []   # 같은 DB에서 재조회된 매칭 결과(0..N)

class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str] = None
    title: str
    mapping_status: Optional[str] = None
    regulation: Optional[str] = None
    auditable: Optional[str] = None
    audit_method: Optional[str] = None
    recommended_fix: Optional[str] = None
    applicable_compliance: Optional[str] = None
    # ✅ SAGE-Threat 전용 확장 필드
    applicable_hits: Optional[List[ApplicableComplianceHitOut]] = None
    model_config = FROM_ATTRS

class MappingOut(BaseModel):
    code: str
    category: Optional[str] = None
    service: Optional[str] = None
    console_path: Optional[str] = None
    check_how: Optional[str] = None
    cli_cmd: Optional[str] = None
    return_field: Optional[str] = None
    compliant_value: Optional[str] = None
    non_compliant_value: Optional[str] = None
    console_fix: Optional[str] = None
    cli_fix_cmd: Optional[str] = None
    model_config = FROM_ATTRS

class RequirementDetailOut(BaseModel):
    framework: str
    requirement: RequirementRowOut
    regulation: Optional[str] = None
    mappings: List[MappingOut]
    model_config = FROM_ATTRS
