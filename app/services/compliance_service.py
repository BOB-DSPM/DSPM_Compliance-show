# app/services/compliance_service.py
from __future__ import annotations

from typing import List, Optional, Iterable, Tuple, Dict
import re

from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from ..models import (
    Framework,
    Requirement,
    Mapping,
    RequirementMapping,
    ThreatGroup,
    ThreatGroupMap,
)
from ..schemas import (
    FrameworkCountOut,
    RequirementRowOut,
    MappingOut,
    RequirementDetailOut,
    RequirementMiniOut,
    ApplicableComplianceHitOut,
)


def ensure_tables(engine) -> None:
    from ..core.db import Base
    Base.metadata.create_all(bind=engine)


def framework_counts(db: Session) -> List[FrameworkCountOut]:
    rows = db.execute(
        select(Requirement.framework_code, Requirement.id)
    ).all()
    # DB-agnostic 집계(Python 쪽에서 count)
    counts: Dict[str, int] = {}
    for fcode, _ in rows:
        counts[fcode] = counts.get(fcode, 0) + 1
    return [FrameworkCountOut(framework=k, count=v) for k, v in sorted(counts.items())]


def _extract_regulation_text(req: Requirement) -> Optional[str]:
    for field in ("regulation", "reg_text", "description", "content", "detail", "body"):
        if hasattr(req, field):
            val = getattr(req, field)
            if val:
                return str(val)
    return None


_CODE_TITLE_RE = re.compile(r"^\s*([0-9][\d\.]*)\s*(.*)$")


def _split_tokens(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(";") if t.strip()]


def _parse_code_title(token: str) -> tuple[Optional[str], Optional[str]]:
    m = _CODE_TITLE_RE.match(token)
    if not m:
        return None, token.strip() or None
    code = (m.group(1) or "").strip() or None
    title = (m.group(2) or "").strip() or None
    return code, title


def _mini_from_row(r: Requirement) -> RequirementMiniOut:
    return RequirementMiniOut(
        id=r.id,
        framework_code=r.framework_code,
        item_code=r.item_code,
        title=r.title,
        regulation=_extract_regulation_text(r) or getattr(r, "description", None),
    )


def _query_matches_for_token(db: Session, code: Optional[str], title: Optional[str]) -> List[RequirementMiniOut]:
    q = db.query(Requirement).filter(Requirement.framework_code != "SAGE-Threat")
    conds = []
    if code:
        conds.append(Requirement.item_code == code)
    if title:
        conds.append(Requirement.title.ilike(f"%{title}%"))
    if not conds:
        return []
    rows = q.filter(or_(*conds)).order_by(Requirement.framework_code, Requirement.id).all()
    return [_mini_from_row(r) for r in rows]


def _build_applicable_hits(db: Session, applicable_compliance: Optional[str]) -> List[ApplicableComplianceHitOut]:
    hits: List[ApplicableComplianceHitOut] = []
    for token in _split_tokens(applicable_compliance):
        code, title = _parse_code_title(token)
        matches = _query_matches_for_token(db, code, title)
        hits.append(ApplicableComplianceHitOut(raw=token, code=code, title=title, matches=matches))
    return hits


def _find_threats_for_requirement(db: Session, item_code: Optional[str], title: Optional[str]) -> List[RequirementMiniOut]:
    """
    (비 SAGE-Threat 요건) → 역방향으로 SAGE-Threat 요건들을 찾아 반환
    기준: SAGE-Threat.requirements.applicable_compliance 에 item_code 또는 title 일부가 포함
    """
    conds = []
    if item_code:
        conds.append(Requirement.applicable_compliance.ilike(f"%{item_code}%"))
    if title:
        key = title.strip()
        if len(key) > 64:
            key = key[:64]
        conds.append(Requirement.applicable_compliance.ilike(f"%{key}%"))
    if not conds:
        return []
    rows = (
        db.query(Requirement)
        .filter(Requirement.framework_code == "SAGE-Threat")
        .filter(or_(*conds))
        .order_by(Requirement.id)
        .all()
    )
    return [_mini_from_row(r) for r in rows]


def _groups_for_threat_requirement_ids(db: Session, threat_req_ids: Iterable[int]) -> List[str]:
    """
    주어진 SAGE-Threat requirement.id 들이 속한 ThreatGroup 이름들을 중복 제거하여 반환
    """
    ids = list({i for i in threat_req_ids if i})
    if not ids:
        return []
    rows = (
        db.query(ThreatGroup.name)
        .join(ThreatGroupMap, ThreatGroupMap.group_id == ThreatGroup.id)
        .filter(ThreatGroupMap.requirement_id.in_(ids))
        .order_by(ThreatGroup.name)
        .all()
    )
    names = [r[0] for r in rows]  # rows: List[Tuple[str]]
    seen, uniq = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _groups_for_single_threat_requirement(db: Session, threat_req_id: int) -> List[str]:
    if not threat_req_id:
        return []
    rows = (
        db.query(ThreatGroup.name)
        .join(ThreatGroupMap, ThreatGroupMap.group_id == ThreatGroup.id)
        .filter(ThreatGroupMap.requirement_id == threat_req_id)
        .order_by(ThreatGroup.name)
        .all()
    )
    names = [r[0] for r in rows]
    seen, uniq = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def list_requirements(db: Session, framework_code: str) -> List[RequirementRowOut]:
    """
    - SAGE-Threat: 위협 그룹명을 포함(threat_groups)하여 반환 + applicable_hits(정방향)
    - 그 외     : threat_hits(역방향) + threat_groups(역방향 매칭된 위협들이 속한 그룹명)
    """
    # ───────── SAGE-Threat (정방향) ─────────
    if framework_code == "SAGE-Threat":
        # DB-agnostic: 조인 결과를 파이썬에서 그룹핑
        rows = db.execute(
            select(
                Requirement.id,
                Requirement.item_code,
                Requirement.title,
                Requirement.mapping_status,
                Requirement.description,
                Requirement.auditable,
                Requirement.audit_method,
                Requirement.recommended_fix,
                Requirement.applicable_compliance,
                ThreatGroup.name.label("group_name"),
            )
            .select_from(Requirement)
            .join(ThreatGroupMap, ThreatGroupMap.requirement_id == Requirement.id, isouter=True)
            .join(ThreatGroup, ThreatGroup.id == ThreatGroupMap.group_id, isouter=True)
            .where(Requirement.framework_code == "SAGE-Threat")
            .order_by(Requirement.id)
        ).all()

        # id별로 그룹명 모으기
        bucket: Dict[int, Dict[str, object]] = {}
        for r in rows:
            m = r._mapping
            rid = m["id"]
            if rid not in bucket:
                bucket[rid] = {
                    "id": m["id"],
                    "item_code": m["item_code"],
                    "title": m["title"],
                    "mapping_status": m["mapping_status"],
                    "regulation": m["description"],
                    "auditable": m["auditable"],
                    "audit_method": m["audit_method"],
                    "recommended_fix": m["recommended_fix"],
                    "applicable_compliance": m["applicable_compliance"],
                    "threat_groups": [],
                }
            g = m["group_name"]
            if g and g not in bucket[rid]["threat_groups"]:
                bucket[rid]["threat_groups"].append(g)  # type: ignore

        out: List[RequirementRowOut] = []
        for data in bucket.values():
            model = RequirementRowOut.model_validate(data)
            hits = _build_applicable_hits(db, model.applicable_compliance)
            out.append(model.model_copy(update={"applicable_hits": hits}))
        # 혹시 조인 결과가 전혀 없었을 때(그룹이 하나도 없고 조인 미적용) 대비
        if not out:
            base_rows = (
                db.query(Requirement)
                .filter(Requirement.framework_code == "SAGE-Threat")
                .order_by(Requirement.id)
                .all()
            )
            for r in base_rows:
                model = RequirementRowOut.model_validate({
                    "id": r.id,
                    "item_code": r.item_code,
                    "title": r.title,
                    "mapping_status": r.mapping_status,
                    "regulation": r.description,
                    "auditable": r.auditable,
                    "audit_method": r.audit_method,
                    "recommended_fix": getattr(r, "recommended_fix", None),
                    "applicable_compliance": getattr(r, "applicable_compliance", None),
                    "threat_groups": _groups_for_single_threat_requirement(db, r.id),
                })
                hits = _build_applicable_hits(db, model.applicable_compliance)
                out.append(model.model_copy(update={"applicable_hits": hits}))
        return out

    # ───────── 비 SAGE-Threat (역방향) ─────────
    stmt = (
        select(
            Requirement.id.label("id"),
            Requirement.item_code.label("item_code"),
            Requirement.title.label("title"),
            Requirement.mapping_status.label("mapping_status"),
            Requirement.description.label("regulation"),
            Requirement.auditable.label("auditable"),
            Requirement.audit_method.label("audit_method"),
            Requirement.recommended_fix.label("recommended_fix"),
            Requirement.applicable_compliance.label("applicable_compliance"),
        )
        .select_from(Requirement)
        .where(Requirement.framework_code == framework_code)
        .order_by(Requirement.id)
    )
    rows = db.execute(stmt).all()

    out: List[RequirementRowOut] = []
    for r in rows:
        data = dict(r._mapping)
        model = RequirementRowOut.model_validate({**data, "threat_groups": []})

        # 역방향: 이 요건과 매칭되는 SAGE-Threat 들
        threats = _find_threats_for_requirement(db, model.item_code, model.title)
        # 해당 위협들이 속한 그룹명(중복 제거)
        threat_ids = [t.id for t in threats]
        groups = _groups_for_threat_requirement_ids(db, threat_ids)

        out.append(
            model.model_copy(update={"threat_hits": threats, "threat_groups": groups})
        )
    return out


def requirement_detail(db: Session, code: str, req_id: int) -> Optional[RequirementDetailOut]:
    req = (
        db.query(Requirement)
        .filter(Requirement.framework_code == code, Requirement.id == req_id)
        .first()
    )
    if not req:
        return None

    maps = (
        db.query(Mapping)
        .join(RequirementMapping, RequirementMapping.mapping_code == Mapping.code)
        .filter(RequirementMapping.requirement_id == req.id)
        .all()
    )

    req_out = RequirementRowOut.model_validate(req)

    if code == "SAGE-Threat":
        hits = _build_applicable_hits(db, getattr(req, "applicable_compliance", None))
        groups = _groups_for_single_threat_requirement(db, req.id)
        req_out = req_out.model_copy(update={"applicable_hits": hits, "threat_groups": groups})
    else:
        th = _find_threats_for_requirement(db, req.item_code, req.title)
        th_ids = [t.id for t in th]
        groups = _groups_for_threat_requirement_ids(db, th_ids)
        req_out = req_out.model_copy(update={"threat_hits": th, "threat_groups": groups})

    return RequirementDetailOut(
        framework=req.framework_code,
        regulation=_extract_regulation_text(req),
        requirement=req_out,
        mappings=[MappingOut.model_validate(m) for m in maps],
    )
