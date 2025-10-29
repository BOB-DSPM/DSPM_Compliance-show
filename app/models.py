# app/models.py
from __future__ import annotations
from typing import List
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .core.db import Base

class Framework(Base):
    __tablename__ = "frameworks"
    code: Mapped[str] = mapped_column(String(64), primary_key=True)     # 예: ISMS-P, GDPR, iso-27001
    name: Mapped[str] = mapped_column(String(128))
    requirements: Mapped[List["Requirement"]] = relationship(back_populates="framework")

class Requirement(Base):
    __tablename__ = "requirements"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    framework_code: Mapped[str] = mapped_column(ForeignKey("frameworks.code"))
    item_code: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    mapping_status: Mapped[str | None] = mapped_column(String(64))
    auditable: Mapped[str | None] = mapped_column(String(64))
    audit_method: Mapped[str | None] = mapped_column(Text)
    recommended_fix: Mapped[str | None] = mapped_column(Text)
    applicable_compliance: Mapped[str | None] = mapped_column(String(16))

    framework: Mapped["Framework"] = relationship(back_populates="requirements")

    mappings: Mapped[List["Mapping"]] = relationship(
        secondary="requirement_mapping", back_populates="requirements"
    )

    # ⬇️ 새 관계: 위협 그룹들
    threat_groups: Mapped[List["ThreatGroup"]] = relationship(
        secondary="threat_group_map", back_populates="requirements"
    )

class Mapping(Base):
    __tablename__ = "mappings"
    code: Mapped[str] = mapped_column(String(16), primary_key=True)
    category: Mapped[str | None] = mapped_column(String(64))
    service: Mapped[str | None] = mapped_column(String(64))
    console_path: Mapped[str | None] = mapped_column(Text)
    check_how: Mapped[str | None] = mapped_column(Text)
    cli_cmd: Mapped[str | None] = mapped_column(Text)
    return_field: Mapped[str | None] = mapped_column(String(128))
    compliant_value: Mapped[str | None] = mapped_column(String(128))
    non_compliant_value: Mapped[str | None] = mapped_column(String(128))
    console_fix: Mapped[str | None] = mapped_column(Text)
    cli_fix_cmd: Mapped[str | None] = mapped_column(Text)

    requirements: Mapped[List["Requirement"]] = relationship(
        secondary="requirement_mapping", back_populates="mappings"
    )

class RequirementMapping(Base):
    __tablename__ = "requirement_mapping"
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"), primary_key=True)
    mapping_code: Mapped[str] = mapped_column(ForeignKey("mappings.code"), primary_key=True)
    relation_type: Mapped[str] = mapped_column(String(16), default="direct")  # direct/partial/na

# ⬇️ 새 테이블들
class ThreatGroup(Base):
    __tablename__ = "threat_groups"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    requirements: Mapped[List["Requirement"]] = relationship(
        secondary="threat_group_map", back_populates="threat_groups"
    )

class ThreatGroupMap(Base):
    __tablename__ = "threat_group_map"
    group_id: Mapped[int] = mapped_column(ForeignKey("threat_groups.id"), primary_key=True)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"), primary_key=True)
