# app/models.py
from __future__ import annotations
from typing import List
from sqlalchemy import String, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .core.db import Base

# ---------- 프레임워크 ----------

class Framework(Base):
    __tablename__ = "frameworks"
    code: Mapped[str] = mapped_column(String(64), primary_key=True)     # 예: ISMS-P, GDPR, iso-27001
    name: Mapped[str] = mapped_column(String(128))
    requirements: Mapped[List["Requirement"]] = relationship(back_populates="framework")

# ---------- 요구사항 ----------

class Requirement(Base):
    __tablename__ = "requirements"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    framework_code: Mapped[str] = mapped_column(ForeignKey("frameworks.code"), index=True)
    item_code: Mapped[str | None] = mapped_column(String(128))          # CSV: 세부항목
    title: Mapped[str] = mapped_column(String(512))                     # 표시용 제목
    description: Mapped[str] = mapped_column(Text)                      # CSV: 규제내용
    mapping_status: Mapped[str | None] = mapped_column(String(64))      # CSV: 매핑여부
    auditable: Mapped[str | None] = mapped_column(String(64))           # CSV: 감사가능
    # 64 → Text (긴 설명 수용)
    audit_method: Mapped[str | None] = mapped_column(Text)              # CSV: 감사방법(AWS 콘솔/CLI)
    # NEW: 권장 해결 요약
    recommended_fix: Mapped[str | None] = mapped_column(Text)
    # CHANGE: 적용 컴플라이언스 내용이 길 수 있어 Text로 확장
    applicable_compliance: Mapped[str | None] = mapped_column(Text)

    framework: Mapped["Framework"] = relationship(back_populates="requirements")
    mappings: Mapped[List["Mapping"]] = relationship(
        secondary="requirement_mapping", back_populates="requirements"
    )

# ---------- 매핑 ----------

class Mapping(Base):
    __tablename__ = "mappings"
    code: Mapped[str] = mapped_column(String(32), primary_key=True)     # 예: 1.0-01, 15.0-4 등 여유 확보
    category: Mapped[str | None] = mapped_column(String(64))            # 예: 1 (접근제어/..)
    service: Mapped[str | None] = mapped_column(String(64))
    # NEW: 리소스(AWS 엔티티) - 세미콜론/콤마 구분 텍스트 그대로 저장
    resource_entities: Mapped[str | None] = mapped_column(Text)
    console_path: Mapped[str | None] = mapped_column(Text)
    check_how: Mapped[str | None] = mapped_column(Text)
    cli_cmd: Mapped[str | None] = mapped_column(Text)
    return_field: Mapped[str | None] = mapped_column(String(256))
    compliant_value: Mapped[str | None] = mapped_column(String(256))
    non_compliant_value: Mapped[str | None] = mapped_column(String(256))
    console_fix: Mapped[str | None] = mapped_column(Text)
    cli_fix_cmd: Mapped[str | None] = mapped_column(Text)

    requirements: Mapped[List["Requirement"]] = relationship(
        secondary="requirement_mapping", back_populates="mappings"
    )

# ---------- 요구사항-매핑 관계 ----------

class RequirementMapping(Base):
    __tablename__ = "requirement_mapping"
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"), primary_key=True, index=True)
    mapping_code: Mapped[str] = mapped_column(ForeignKey("mappings.code"), primary_key=True, index=True)
    relation_type: Mapped[str] = mapped_column(String(16), default="direct")  # direct/partial/na

# ---------- 위협 그룹/위협 ----------

class ThreatGroup(Base):
    __tablename__ = "threat_groups"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # 예: "권한/계정 관리 문제"
    threats: Mapped[List["Threat"]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan"
    )

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("threat_groups.id"), index=True)
    title: Mapped[str] = mapped_column(String(512))  # 예: "내부자 과도한 권한 및 오남용"

    group: Mapped["ThreatGroup"] = relationship(back_populates="threats")

    __table_args__ = (
        UniqueConstraint("group_id", "title", name="uq_threat_group_title"),
    )
