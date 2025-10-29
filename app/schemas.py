# app/schemas.py
from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field

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
    raw: str
    code: Optional[str] = None
    title: Optional[str] = None
    matches: List[RequirementMiniOut] = Field(default_factory=list)

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
    # ⬇️ 추가: 이 위협 항목이 속한 그룹들
    threat_groups: Optional[List[str]] = None

    # SAGE-Threat(정방향)
    applicable_hits: Optional[List[ApplicableComplianceHitOut]] = None
    # 역방향(컴플라이언스 → 관련 위협들)
    threat_hits: Optional[List[RequirementMiniOut]] = None
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
