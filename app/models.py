# app/models.py
from __future__ import annotations
from typing import List, Optional

from sqlalchemy import (
    String,
    Text,
    ForeignKey,
    Integer,
    UniqueConstraint,
    Index,  # ★ 추가
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .core.db import Base


# ─────────────────────────
# Framework / Requirement
# ─────────────────────────
class Framework(Base):
    __tablename__ = "frameworks"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)  # 예: ISMS-P, GDPR, SAGE-Threat
    name: Mapped[str] = mapped_column(String(128))

    requirements: Mapped[List["Requirement"]] = relationship(back_populates="framework")


class Requirement(Base):
    __tablename__ = "requirements"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    framework_code: Mapped[str] = mapped_column(ForeignKey("frameworks.code"))
    item_code: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mapping_status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    auditable: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    audit_method: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # ★ 긴 문장 대비해 Text 로
    applicable_compliance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    framework: Mapped["Framework"] = relationship(back_populates="requirements")

    # Requirement ↔ Mapping (다대다)
    mappings: Mapped[List["Mapping"]] = relationship(
        secondary="requirement_mappings",
        back_populates="requirements",
        viewonly=True,
    )

    # Requirement ↔ ThreatGroup (다대다)
    threat_groups: Mapped[List["ThreatGroup"]] = relationship(
        secondary="threat_group_maps",  # ★ 복수형 테이블명으로 수정
        back_populates="requirements",
        viewonly=True,
    )


# ─────────────────────────
# Mapping / RequirementMapping
# ─────────────────────────
class Mapping(Base):
    __tablename__ = "mappings"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    console_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    check_how: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cli_cmd: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    return_field: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    compliant_value: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    non_compliant_value: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    console_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cli_fix_cmd: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    requirements: Mapped[List["Requirement"]] = relationship(
        secondary="requirement_mappings",
        back_populates="mappings",
        viewonly=True,
    )


class RequirementMapping(Base):
    """
    Requirement(id) ↔ Mapping(code) 연결 테이블
    """
    __tablename__ = "requirement_mappings"
    __table_args__ = (
        UniqueConstraint("requirement_id", "mapping_code", name="uq_req_map"),
    )

    requirement_id: Mapped[int] = mapped_column(
        ForeignKey("requirements.id"), primary_key=True
    )
    mapping_code: Mapped[str] = mapped_column(
        ForeignKey("mappings.code"), primary_key=True
    )
    relation_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default="direct")


# ─────────────────────────
# ThreatGroup / ThreatGroupMap
# ─────────────────────────
class ThreatGroup(Base):
    __tablename__ = "threat_groups"
    __table_args__ = (UniqueConstraint("name", name="uq_threat_group_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), index=True)

    # ★ Requirement 와의 다대다 역관계 추가
    requirements: Mapped[List["Requirement"]] = relationship(
        secondary="threat_group_maps",
        back_populates="threat_groups",
        viewonly=True,
    )

    # 선택: 매핑 레코드 직접 접근이 필요하면 유지
    maps: Mapped[List["ThreatGroupMap"]] = relationship(
        back_populates="group",
        cascade="all,delete-orphan"
    )


class ThreatGroupMap(Base):
    """
    ThreatGroup(id) ↔ Requirement(id) 연결 테이블
    - SAGE-Threat 프레임워크의 각 위협 요건들을 위협 그룹과 매핑
    """
    __tablename__ = "threat_group_maps"
    __table_args__ = (
        UniqueConstraint("group_id", "requirement_id", name="uq_group_req"),
        Index("ix_tgm_group_req", "group_id", "requirement_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("threat_groups.id", ondelete="CASCADE"), index=True)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id", ondelete="CASCADE"), index=True)

    group: Mapped["ThreatGroup"] = relationship(back_populates="maps")
    requirement: Mapped["Requirement"] = relationship(viewonly=True)
