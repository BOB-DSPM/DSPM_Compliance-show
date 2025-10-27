from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel

class FrameworkCountOut(BaseModel):
    framework: str
    count: int
class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str]
    title: str
    mapping_status: Optional[str]
    regulation: Optional[str]  # = description
    auditable: Optional[str]
    audit_method: Optional[str]

    # ✅ 새 필드 추가
    recommended_fix: Optional[str]
    applicable_compliance: Optional[str]

    class Config:
        orm_mode = True

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
        orm_mode = True

class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str]
    title: str
    mapping_status: Optional[str]
    regulation: Optional[str]  # = description
    auditable: Optional[str]
    audit_method: Optional[str]

    # ✅ 새 필드 추가
    recommended_fix: Optional[str]
    applicable_compliance: Optional[str]

    class Config:
        orm_mode = True


class RequirementDetailOut(BaseModel):
    framework: str
    requirement: RequirementRowOut
    regulation: Optional[str]
    mappings: List[MappingOut]

    class Config:
        orm_mode = True