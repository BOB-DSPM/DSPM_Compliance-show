# app/schemas.py
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel

class FrameworkCountOut(BaseModel):
    framework: str
    count: int

class RequirementMiniOut(BaseModel):
    id: int
    framework_code: str
    item_code: Optional[str] = None
    title: str
    regulation: Optional[str] = None

class ApplicableComplianceHitOut(BaseModel):
    raw: str
    code: Optional[str] = None
    title: Optional[str] = None
    matches: List[RequirementMiniOut] = []

class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str]
    title: str
    mapping_status: Optional[str]
    regulation: Optional[str]
    auditable: Optional[str]
    audit_method: Optional[str]
    recommended_fix: Optional[str]
    applicable_compliance: Optional[str]
    # SAGE-Threat 전용(서비스에서 주입)
    applicable_hits: Optional[List[ApplicableComplianceHitOut]] = None

    class Config:
        from_attributes = True  # ✅ Pydantic v2

class RequirementRowWithGroupsOut(RequirementRowOut):
    # 대표 그룹(단수) + 후보(복수)
    threat_group: Optional[str] = None
    threat_groups: Optional[List[str]] = None

class MappingOut(BaseModel):
    code: str
    category: Optional[str]
    service: Optional[str]
    console_path: Optional[str]
    check_how: Optional[str]
    cli_cmd: Optional[str]
    return_field: Optional[str]
    compliant_value: Optional[str]
    non_compliant_value: Optional[str]
    console_fix: Optional[str]
    cli_fix_cmd: Optional[str]

    class Config:
        from_attributes = True

class RequirementDetailOut(BaseModel):
    framework: str
    regulation: Optional[str]
    requirement: RequirementRowOut
    mappings: List[MappingOut]

class RequirementDetailWithGroupsOut(BaseModel):
    framework: str
    regulation: Optional[str]
    requirement: RequirementRowWithGroupsOut
    mappings: List[MappingOut]
