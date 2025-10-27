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
    regulation: Optional[str] = None

class MappingOut(BaseModel):
    code: str
    category: str | None = None
    service: str | None = None
    console_path: str | None = None
    check_how: str | None = None
    cli_cmd: str | None = None
    return_field: str | None = None
    compliant_value: str | None = None
    non_compliant_value: str | None = None
    console_fix: str | None = None
    cli_fix_cmd: str | None = None

class RequirementDetailOut(BaseModel):
    framework: str
    requirement: RequirementRowOut
    regulation: Optional[str] = None
    mappings: List[MappingOut]
