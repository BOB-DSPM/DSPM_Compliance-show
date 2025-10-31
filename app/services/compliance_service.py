# app/services/compliance_service.py
from __future__ import annotations

import re
from typing import List, Optional, Iterable, Tuple, Set

from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session

from ..models import (
    Framework,
    Requirement,
    Mapping,
    RequirementMapping,
    ThreatGroup,
    Threat,
)

from ..schemas import (
    FrameworkCountOut,
    RequirementRowOut,
    MappingOut,
    RequirementDetailOut,
    RequirementMiniOut,
    ApplicableComplianceHitOut,
    RequirementRowWithGroupsOut,
    RequirementDetailWithGroupsOut,
    # 신규(위협 매핑)
    ThreatMiniOut,
    RequirementRowWithThreatsOut,
    RequirementDetailWithThreatsOut,
)

# -----------------------------------------------------------------------------
# 공통 유틸
# -----------------------------------------------------------------------------
def ensure_tables(engine) -> None:
    from ..core.db import Base
    Base.metadata.create_all(bind=engine)

def _extract_regulation_text(req: Requirement) -> Optional[str]:
    for field in ("regulation", "reg_text", "description", "content", "detail", "body"):
        if hasattr(req, field):
            val = getattr(req, field)
            if val:
                return str(val)
    return None

def framework_counts(db: Session) -> List[FrameworkCountOut]:
    rows = (
        db.execute(
            select(Requirement.framework_code, func.count(Requirement.id))
            .group_by(Requirement.framework_code)
            .order_by(Requirement.framework_code)
        )
        .all()
    )
    return [FrameworkCountOut(framework=f, count=c) for (f, c) in rows]

# -----------------------------------------------------------------------------
# applicable_compliance 파싱/재조회 (SAGE-Threat 전용 역참조)
# -----------------------------------------------------------------------------
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

def _query_matches_for_token(
    db: Session, code: Optional[str], title: Optional[str]
) -> List[RequirementMiniOut]:
    q = db.query(Requirement).filter(Requirement.framework_code != "SAGE-Threat")
    conds = []
    if code:
        conds.append(Requirement.item_code == code)
    if title:
        conds.append(Requirement.title.ilike(f"%{title}%"))
    if not conds:
        return []
    rows = q.filter(or_(*conds)).order_by(Requirement.framework_code, Requirement.id).all()
    out: List[RequirementMiniOut] = []
    for r in rows:
        out.append(
            RequirementMiniOut(
                id=r.id,
                framework_code=r.framework_code,
                item_code=r.item_code,
                title=r.title,
                regulation=_extract_regulation_text(r) or getattr(r, "description", None),
            )
        )
    return out

def _build_applicable_hits(
    db: Session, applicable_compliance: Optional[str]
) -> List[ApplicableComplianceHitOut]:
    hits: List[ApplicableComplianceHitOut] = []
    for token in _split_tokens(applicable_compliance):
        code, title = _parse_code_title(token)
        matches = _query_matches_for_token(db, code, title)
        hits.append(
            ApplicableComplianceHitOut(raw=token, code=code, title=title, matches=matches)
        )
    return hits

# -----------------------------------------------------------------------------
# 기본 목록/상세 (매핑 코드/서비스 동반 반환)
# -----------------------------------------------------------------------------
def list_requirements(db: Session, framework_code: str) -> List[RequirementRowOut]:
    """
    목록 API에서 각 항목별 매핑 코드들과 매핑 서비스들을 함께 반환한다.
    - SQLite: group_concat 사용(중복은 파이썬에서 제거)
    """
    mapping_codes_csv = func.group_concat(RequirementMapping.mapping_code, ";")
    mapping_services_csv = func.group_concat(Mapping.service, ";")

    rows = (
        db.query(
            Requirement.id.label("id"),
            Requirement.item_code.label("item_code"),
            Requirement.title.label("title"),
            Requirement.mapping_status.label("mapping_status"),
            Requirement.description.label("regulation"),
            Requirement.auditable.label("auditable"),
            Requirement.audit_method.label("audit_method"),
            Requirement.recommended_fix.label("recommended_fix"),
            Requirement.applicable_compliance.label("applicable_compliance"),
            mapping_codes_csv.label("mapping_codes_csv"),
            mapping_services_csv.label("mapping_services_csv"),
        )
        .outerjoin(RequirementMapping, RequirementMapping.requirement_id == Requirement.id)
        .outerjoin(Mapping, Mapping.code == RequirementMapping.mapping_code)
        .filter(Requirement.framework_code == framework_code)
        .group_by(
            Requirement.id,
            Requirement.item_code,
            Requirement.title,
            Requirement.mapping_status,
            Requirement.description,
            Requirement.auditable,
            Requirement.audit_method,
            Requirement.recommended_fix,
            Requirement.applicable_compliance,
        )
        .order_by(Requirement.id)
        .all()
    )

    def _split_csv(val: str | None) -> List[str]:
        if not val:
            return []
        parts = [p.strip() for p in val.split(";") if p.strip()]
        # 중복 제거(순서 보존)
        seen, uniq = set(), []
        for x in parts:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        return uniq

    models: List[RequirementRowOut] = []
    for r in rows:
        d = dict(r._mapping)
        codes = _split_csv(d.pop("mapping_codes_csv", None))
        services = _split_csv(d.pop("mapping_services_csv", None))
        d["mapping_codes"] = codes or None
        d["mapping_services"] = services or None
        models.append(RequirementRowOut.model_validate(d))

    # SAGE-Threat 프레임워크(=위협 카탈로그)만 applicable_hits 역참조 제공
    if framework_code == "SAGE-Threat":
        enriched: List[RequirementRowOut] = []
        for m in models:
            hits = _build_applicable_hits(db, m.applicable_compliance)
            enriched.append(m.model_copy(update={"applicable_hits": hits}))
        return enriched

    return models

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

    reg_text = _extract_regulation_text(req)
    mapping_codes = [m.code for m in maps if getattr(m, "code", None)]

    # 상세에도 매핑 서비스 리스트 제공
    mapping_services: List[str] = []
    seen = set()
    for m in maps:
        s = (m.service or "").strip()
        if s and s not in seen:
            seen.add(s)
            mapping_services.append(s)

    req_out = RequirementRowOut.model_validate(req).model_copy(
        update={
            "regulation": reg_text,
            "mapping_codes": mapping_codes or None,
            "mapping_services": mapping_services or None,
        }
    )

    # SAGE-Threat(위협 카탈로그)일 때만 applicable_hits 제공
    if code == "SAGE-Threat":
        hits = _build_applicable_hits(db, getattr(req, "applicable_compliance", None))
        req_out = req_out.model_copy(update={"applicable_hits": hits})

    return RequirementDetailOut(
        framework=req.framework_code,
        regulation=reg_text,
        requirement=req_out,
        mappings=[MappingOut.model_validate(m) for m in maps],
    )

# -----------------------------------------------------------------------------
# ThreatGroup 매핑(그룹명 추가) — 기존 동작 유지(SAGE-Threat 전용)
# -----------------------------------------------------------------------------
def _norm_text(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _candidate_groups(db: Session, title: Optional[str]) -> List[str]:
    """
    title로 ThreatGroup 후보 전부 수집(정확→부분). 중복 제거, 원문 표기 유지.
    """
    t = _norm_text(title)
    if not t:
        return []
    names: List[str] = []

    exact = (
        db.query(ThreatGroup.name)
        .join(Threat, Threat.group_id == ThreatGroup.id)
        .filter(func.lower(Threat.title) == t)
        .distinct()
        .all()
    )
    names.extend([n for (n,) in exact])
    if names:
        return sorted(set(names))  # 정확 일치 우선

    like_hits = (
        db.query(ThreatGroup.name)
        .join(Threat, Threat.group_id == ThreatGroup.id)
        .filter(Threat.title.ilike(f"%{title}%"))
        .distinct()
        .all()
    )
    names.extend([n for (n,) in like_hits])
    return sorted(set(names))

def _pick_primary_group(candidates: List[str]) -> Optional[str]:
    return candidates[0] if candidates else None

def list_requirements_with_groups(db: Session, framework_code: str) -> List[RequirementRowWithGroupsOut]:
    """
    기존 list_requirements 결과에 threat_group(단수) + threat_groups(복수) 주입.
    SAGE-Threat가 아니면 둘 다 None.
    """
    base_rows = list_requirements(db, framework_code)
    out: List[RequirementRowWithGroupsOut] = []
    is_threat = framework_code == "SAGE-Threat"

    for m in base_rows:
        if is_threat:
            candidates = _candidate_groups(db, m.title)
            primary = _pick_primary_group(candidates)
            out.append(
                RequirementRowWithGroupsOut.model_validate(
                    m.model_dump()
                    | {"threat_group": primary, "threat_groups": candidates or None}
                )
            )
        else:
            out.append(
                RequirementRowWithGroupsOut.model_validate(
                    m.model_dump() | {"threat_group": None, "threat_groups": None}
                )
            )
    return out

def requirement_detail_with_groups(
    db: Session, code: str, req_id: int
) -> Optional[RequirementDetailWithGroupsOut]:
    base = requirement_detail(db, code, req_id)
    if not base:
        return None

    if code == "SAGE-Threat":
        candidates = _candidate_groups(db, base.requirement.title)
        primary = _pick_primary_group(candidates)
        req_with_groups = RequirementRowWithGroupsOut.model_validate(
            base.requirement.model_dump()
            | {"threat_group": primary, "threat_groups": candidates or None}
        )
    else:
        req_with_groups = RequirementRowWithGroupsOut.model_validate(
            base.requirement.model_dump() | {"threat_group": None, "threat_groups": None}
        )

    return RequirementDetailWithGroupsOut(
        framework=base.framework,
        regulation=base.regulation,
        requirement=req_with_groups,
        mappings=base.mappings,
    )

# -----------------------------------------------------------------------------
# 🔶 신규: “컴플라이언스(요구사항) → 개별 위협(Threat)” 자동 제안 매핑
# -----------------------------------------------------------------------------
_WORD_SPLIT_RE = re.compile(r"[^\w\-\./]+")

def _split_free(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [t for t in _WORD_SPLIT_RE.split(s) if t]

def _normalize_token(t: str) -> str:
    return re.sub(r"\s+", " ", t.strip().lower())

def _bag_from_list(items: Iterable[str]) -> Set[str]:
    return {_normalize_token(x) for x in items if x and _normalize_token(x)}

def _join_texts(parts: Iterable[Optional[str]]) -> str:
    return " | ".join([p for p in parts if p])

def _tokenize_requirement(req: RequirementRowOut) -> dict:
    title = getattr(req, "title", "") or ""
    reg = getattr(req, "regulation", None) or ""
    codes = list(getattr(req, "mapping_codes", []) or [])
    svcs = list(getattr(req, "mapping_services", []) or [])

    bag: Set[str] = set()
    bag |= _bag_from_list(_split_free(title))
    bag |= _bag_from_list(_split_free(reg))
    for c in codes:
        bag |= _bag_from_list(_split_free(c))
    for s in svcs:
        bag |= _bag_from_list(_split_free(s))

    return {"title": title, "regulation": reg, "codes": codes, "svcs": svcs, "bag": bag}

def _tokenize_threat(t: Threat, group_name: Optional[str]) -> dict:
    title = getattr(t, "title", "") or ""
    bag: Set[str] = set()
    bag |= _bag_from_list(_split_free(title))
    return {"id": t.id, "title": title, "group_name": group_name, "bag": bag, "map_codes": set()}

def _score_match(req_tok: dict, thr_tok: dict) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    score: float = 0.0

    req_codes = _bag_from_list(req_tok.get("codes", []))
    thr_codes = set(thr_tok.get("map_codes", set()) or set())
    code_hit = req_codes & thr_codes
    if code_hit:
        score += 3.0 * len(code_hit)
        reasons.append(f"mapping_codes 교집합: {sorted(code_hit)}")

    req_svcs = _bag_from_list(req_tok.get("svcs", []))
    svc_hit = req_svcs & thr_tok["bag"]
    if svc_hit:
        score += 2.0 * len(svc_hit)
        reasons.append(f"서비스 키워드 매칭: {sorted(svc_hit)}")

    common = req_tok["bag"] & thr_tok["bag"]
    if common:
        score += 1.0 * len(common)
        reasons.append(f"내용 토큰 교집합 일부: {sorted(list(common))[:10]}")

    return score, reasons

def _suggest_threats_for_requirement(
    db: Session, req: RequirementRowOut, top_k: int = 8, min_score: float = 2.0
) -> List[ThreatMiniOut]:
    req_tok = _tokenize_requirement(req)
    rows = (
        db.query(Threat, ThreatGroup.name.label("group_name"))
        .join(ThreatGroup, Threat.group_id == ThreatGroup.id, isouter=True)
        .all()
    )

    scored: List[Tuple[float, Threat, Optional[str], List[str]]] = []
    for t, gname in rows:
        thr_tok = _tokenize_threat(t, gname)
        s, reasons = _score_match(req_tok, thr_tok)
        if s >= min_score:
            scored.append((s, t, gname, reasons))

    scored.sort(key=lambda x: x[0], reverse=True)

    out: List[ThreatMiniOut] = []
    for s, t, gname, reasons in scored[:top_k]:
        out.append(
            ThreatMiniOut(
                id=t.id,
                title=t.title,
                group_name=gname,
                score=float(s),
                reasons=reasons,
            )
        )
    return out

# -----------------------------------------------------------------------------
# 🔶 신규: 고정 위협 매핑(포함 검색) — 내 컴플라이언스 문자열 ↔ SAGE-Threat.applicable_compliance
# -----------------------------------------------------------------------------
def _like_patterns_from_requirement(m: RequirementRowOut) -> List[str]:
    pats: List[str] = []
    item = (m.item_code or "").strip()
    title = (m.title or "").strip()
    if item and len(item) > 2:
        pats.append(item)
    if title and len(title) > 2:
        pats.append(title)
    # 중복 제거(순서 보존)
    seen, uniq = set(), []
    for p in pats:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

def _find_fixed_threats_for_requirement(db: Session, m: RequirementRowOut, top_k: int = 12) -> List[ThreatMiniOut]:
    pats = _like_patterns_from_requirement(m)
    if not pats:
        return []

    q = db.query(Requirement).filter(Requirement.framework_code == "SAGE-Threat")
    like_conds = []
    for p in pats:
        like_conds.append(Requirement.applicable_compliance.ilike(f"%{p}%"))
        like_conds.append(Requirement.title.ilike(f"%{p}%"))
        like_conds.append(Requirement.description.ilike(f"%{p}%"))
    q = q.filter(or_(*like_conds)).order_by(Requirement.id.desc())

    rows = q.limit(top_k * 3).all()

    out: List[ThreatMiniOut] = []
    seen_titles: Set[str] = set()
    for r in rows:
        candidates = _candidate_groups(db, r.title)
        primary = _pick_primary_group(candidates)
        reasons = []
        ac = (getattr(r, "applicable_compliance", "") or "")
        for p in pats:
            if p.lower() in ac.lower():
                reasons.append(f"applicable_compliance 포함: '{p}'")
            elif p.lower() in (r.title or "").lower():
                reasons.append(f"title 포함: '{p}'")
            elif p.lower() in (r.description or "").lower():
                reasons.append(f"regulation 포함: '{p}'")

        key = (r.title or "").strip().lower()
        if key and key in seen_titles:
            continue
        seen_titles.add(key)

        out.append(
            ThreatMiniOut(
                id=r.id,                 # SAGE-Threat Requirement.id (상세 링크용)
                title=r.title,
                group_name=primary,
                score=None,
                reasons=reasons or None,
            )
        )
        if len(out) >= top_k:
            break
    return out

# -----------------------------------------------------------------------------
# 목록/상세 with Threats (컴플라이언스 → 위협)
# -----------------------------------------------------------------------------
def list_requirements_with_threats(db: Session, framework_code: str) -> List[RequirementRowWithThreatsOut]:
    base_rows = list_requirements(db, framework_code)
    out: List[RequirementRowWithThreatsOut] = []

    for m in base_rows:
        fixed = _find_fixed_threats_for_requirement(db, m) or []
        suggested = _suggest_threats_for_requirement(db, m) or []

        # 통합(threats): 제목 기준 dedup
        merged: List[ThreatMiniOut] = []
        seen = set()
        for lst in (fixed, suggested):
            for t in lst:
                k = (t.title or "").strip().lower()
                if not k or k in seen:
                    continue
                seen.add(k)
                merged.append(t)

        out.append(
            RequirementRowWithThreatsOut.model_validate(
                m.model_dump() | {
                    "fixed_threats": fixed or None,
                    "suggested_threats": suggested or None,
                    "threats": merged or None,
                }
            )
        )
    return out

def requirement_detail_with_threats(
    db: Session, code: str, req_id: int
) -> Optional[RequirementDetailWithThreatsOut]:
    base = requirement_detail(db, code, req_id)
    if not base:
        return None

    # RequirementRowOut 으로 정규화
    req_row = RequirementRowOut.model_validate(base.requirement.model_dump())
    fixed = _find_fixed_threats_for_requirement(db, req_row) or []
    suggested = _suggest_threats_for_requirement(db, req_row) or []

    merged: List[ThreatMiniOut] = []
    seen = set()
    for lst in (fixed, suggested):
        for t in lst:
            k = (t.title or "").strip().lower()
            if not k or k in seen:
                continue
            seen.add(k)
            merged.append(t)

    req_with_threats = RequirementRowWithThreatsOut.model_validate(
        req_row.model_dump() | {
            "fixed_threats": fixed or None,
            "suggested_threats": suggested or None,
            "threats": merged or None,
        }
    )

    return RequirementDetailWithThreatsOut(
        framework=base.framework,
        regulation=base.regulation,
        requirement=req_with_threats,
        mappings=base.mappings,
    )
