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
    item_code: Mapped[str | None] = mapped_column(String(128))          # 세부항목(예: 2.10.1.2)
    title: Mapped[str] = mapped_column(String(512))                     # 세부항목(표시용)
    description: Mapped[str] = mapped_column(Text)                      # 규제내용
    mapping_status: Mapped[str | None] = mapped_column(String(64))      # 매핑여부
    auditable: Mapped[str | None] = mapped_column(String(64))           # 감사가능
    audit_method: Mapped[str | None] = mapped_column(String(64))        # 감사방법(AWS 콘솔/CLI)

    framework: Mapped["Framework"] = relationship(back_populates="requirements")
    mappings: Mapped[List["Mapping"]] = relationship(
        secondary="requirement_mapping", back_populates="requirements"
    )

class Mapping(Base):
    __tablename__ = "mappings"
    code: Mapped[str] = mapped_column(String(16), primary_key=True)     # 예: 1.0-01
    category: Mapped[str | None] = mapped_column(String(64))            # 예: 1 (접근제어/..)
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
