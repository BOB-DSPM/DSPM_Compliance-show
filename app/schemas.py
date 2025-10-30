# app/schemas.py
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field

# ---------- 공통 ----------

class FrameworkCountOut(BaseModel):
    framework: str
    count: int

# ---------- 적용 컴플라이언스 역참조(미니 레코드) ----------

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
    # ⚠️ 가변 기본값: default_factory로 리스트 생성
    matches: List[RequirementMiniOut] = Field(default_factory=list)

# ---------- 요구사항(행) ----------

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
    mapping_codes: Optional[List[str]] = None
    mapping_services: Optional[List[str]] = None
    # SAGE-Threat 전용(서비스에서 주입)
    applicable_hits: Optional[List[ApplicableComplianceHitOut]] = None

    class Config:
        from_attributes = True  # Pydantic v2

# 위협 그룹명 주입 버전(목록/상세 공용)
class RequirementRowWithGroupsOut(RequirementRowOut):
    # 대표 그룹(단수) + 후보(복수)
    threat_group: Optional[str] = None
    threat_groups: Optional[List[str]] = None

# ---------- 매핑 ----------

class MappingOut(BaseModel):
    code: str
    category: Optional[str] = None
    service: Optional[str] = None
    # NEW: 매핑 리소스 표기(세미콜론/콤마 구분 텍스트로 보관)
    resource_entities: Optional[str] = None
    console_path: Optional[str] = None
    check_how: Optional[str] = None
    cli_cmd: Optional[str] = None
    return_field: Optional[str] = None
    compliant_value: Optional[str] = None
    non_compliant_value: Optional[str] = None
    console_fix: Optional[str] = None
    cli_fix_cmd: Optional[str] = None

    class Config:
        from_attributes = True

# ---------- 상세 ----------

class RequirementDetailOut(BaseModel):
    framework: str
    regulation: Optional[str] = None
    requirement: RequirementRowOut
    mappings: List[MappingOut]

class RequirementDetailWithGroupsOut(BaseModel):
    framework: str
    regulation: Optional[str] = None
    requirement: RequirementRowWithGroupsOut
    mappings: List[MappingOut]
