from __future__ import annotations
from typing import List, Optional

from sqlalchemy import (
    String,
    Text,
    ForeignKey,
    Integer,
    UniqueConstraint,
)
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

    threat_groups: Mapped[list["ThreatGroup"]] = relationship(
        secondary="threat_group_map",
        back_populates="requirements",
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

class ThreatGroup(Base):
    __tablename__ = "threat_groups"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # 역참조
    maps: Mapped[list["ThreatGroupMap"]] = relationship(back_populates="group", cascade="all,delete-orphan")



class ThreatGroupMap(Base):
    __tablename__ = "threat_group_maps"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("threat_groups.id", ondelete="CASCADE"), index=True)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id", ondelete="CASCADE"), index=True)

    group: Mapped["ThreatGroup"] = relationship(back_populates="maps")
    requirement: Mapped["Requirement"] = relationship(viewonly=True)

    __table_args__ = (
        UniqueConstraint("group_id", "requirement_id", name="uq_threat_group_requirement"),
        Index("ix_tgm_group_req", "group_id", "requirement_id"),
    )