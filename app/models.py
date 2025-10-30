from __future__ import annotations
from typing import List
from sqlalchemy import String, Text, ForeignKey, UniqueConstraint 
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .core.db import Base

class Framework(Base):
    __tablename__ = "frameworks"
    code: Mapped[str] = mapped_column(String(64), primary_key=True)     # 예: ISMS-P, GDPR, iso-27001
    name: Mapped[str] = mapped_column(String(128))
    requirements: Mapped[List["Requirement"]] = relationship(back_populates="framework")

# app/models.py (발췌)

class Requirement(Base):
    __tablename__ = "requirements"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    framework_code: Mapped[str] = mapped_column(ForeignKey("frameworks.code"))
    item_code: Mapped[str | None] = mapped_column(String(128))          # CSV: 세부항목
    title: Mapped[str] = mapped_column(String(512))                     # 표시용 제목
    description: Mapped[str] = mapped_column(Text)                      # CSV: 규제내용
    mapping_status: Mapped[str | None] = mapped_column(String(64))      # CSV: 매핑여부
    auditable: Mapped[str | None] = mapped_column(String(64))           # CSV: 감사가능

    # ⬇️ 기존 64 → Text 로 확장 (예: "접근/반출 이벤트 CloudTrail Lake..." 등 64 초과)
    audit_method: Mapped[str | None] = mapped_column(Text)              # CSV: 감사방법(AWS 콘솔/CLI)

    # ⬇️ 신규 CSV 컬럼 반영
    recommended_fix: Mapped[str | None] = mapped_column(Text)           # CSV: 권장해결(요약)
    applicable_compliance: Mapped[str | None] = mapped_column(String(16))  # CSV: 해당컴플 (예/아니오/-)

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

class ThreatGroup(Base):
    __tablename__ = "threat_groups"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # 예: "권한/계정 관리 문제"
    threats: Mapped[List["Threat"]] = relationship(back_populates="group", cascade="all, delete-orphan")

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("threat_groups.id"))
    title: Mapped[str] = mapped_column(String(512))  # 예: "내부자 과도한 권한 및 오남용"
    group: Mapped["ThreatGroup"] = relationship(back_populates="threats")

    __table_args__ = (
        UniqueConstraint("group_id", "title", name="uq_threat_group_title"),
    )

