from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, or_
from sqlalchemy.orm import Session

from app.api.dependencies import get_analysis_or_404
from app.api.routes.system import latest_analysis_ids
from app.database.session import get_db
from app.models.tables import Analysis, EmailSessionRow, EvidenceRow, Finding, FindingStatusHistory, PacketMeta, TlsSessionRow
from app.schemas.api import FindingStatusUpdate
from app.services.audit import audit
from app.services.serializers import SEV_ORDER, evidence_dict, finding_dict, session_dict, tls_dict

router = APIRouter()
SORTS = {"severity": None, "risk": Finding.risk_score, "created": Finding.created_at, "rule": Finding.rule_id, "status": Finding.status, "title": Finding.title}


def _query(db: Session, analysis_ids: list[str] | None, severity, protocol, category, status, rule_id, observation_type, q, sort, order):
    qry = db.query(Finding)
    if analysis_ids is not None:
        qry = qry.filter(Finding.analysis_id.in_(analysis_ids))
    for col, val in ((Finding.severity, severity), (Finding.protocol, protocol.upper() if protocol else None), (Finding.category, category), (Finding.status, status),
                     (Finding.rule_id, rule_id), (Finding.observation_type, observation_type)):
        if val:
            qry = qry.filter(col == val)
    if q:
        like = f"%{q.strip()[:80]}%"
        qry = qry.filter(or_(Finding.title.ilike(like), Finding.rule_id.ilike(like), Finding.description.ilike(like), Finding.ref.ilike(like)))
    if sort == "severity":
        rank = case(*[(Finding.severity == s, i) for s, i in SEV_ORDER.items()], else_=9)
        qry = qry.order_by(rank.desc() if order == "desc" else rank.asc(), Finding.risk_score.desc())
    else:
        col = SORTS.get(sort, Finding.risk_score)
        qry = qry.order_by(col.desc() if order == "desc" else col.asc())
    return qry


def _page(db, qry, page, page_size):
    total = qry.count()
    rows = qry.offset((page - 1) * page_size).limit(page_size).all()
    caps = {}
    items = []
    for f in rows:
        if f.analysis_id not in caps:
            a = db.get(Analysis, f.analysis_id)
            caps[f.analysis_id] = (a.capture.filename, a.capture_id)
        items.append(finding_dict(f, capture_name=caps[f.analysis_id][0], capture_id=caps[f.analysis_id][1]))
    facets = {"severities": list(SEV_ORDER), "statuses": ["open", "under_review", "resolved", "accepted_risk"]}
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)), "facets": facets}


def finding_filters(severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"), protocol: str | None = Query(None, max_length=10),
                    category: str | None = Query(None, max_length=60), status: str | None = Query(None, pattern="^(open|under_review|resolved|accepted_risk)$"),
                    rule_id: str | None = Query(None, max_length=20), observation_type: str | None = Query(None, max_length=24), q: str | None = Query(None, max_length=80),
                    sort: str = Query("severity"), order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)) -> dict:
    return dict(severity=severity, protocol=protocol, category=category, status=status, rule_id=rule_id, observation_type=observation_type, q=q, sort=sort, order=order, page=page, page_size=page_size)


def _run(db, ids, f: dict):
    qry = _query(db, ids, f["severity"], f["protocol"], f["category"], f["status"], f["rule_id"], f["observation_type"], f["q"], f["sort"], f["order"])
    return _page(db, qry, f["page"], f["page_size"])


@router.get("/findings")
def list_findings(f: dict = Depends(finding_filters), analysis_id: str | None = None, db: Session = Depends(get_db)):
    return _run(db, [analysis_id] if analysis_id else latest_analysis_ids(db), f)


@router.get("/analyses/{analysis_id}/findings")
def analysis_findings(a: Analysis = Depends(get_analysis_or_404), f: dict = Depends(finding_filters), db: Session = Depends(get_db)):
    return _run(db, [a.id], f)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    a = db.get(Analysis, f.analysis_id)
    d = finding_dict(f, with_evidence=True, capture_name=a.capture.filename, capture_id=a.capture_id)
    sess = db.query(EmailSessionRow).filter_by(analysis_id=a.id, stream_id=f.stream_id).first() if f.stream_id is not None else None
    tls = db.query(TlsSessionRow).filter_by(analysis_id=a.id, stream_id=f.stream_id).first() if f.stream_id is not None else None
    d["session"] = session_dict(sess) if sess else None
    d["tls_session"] = tls_dict(tls) if tls else None
    d["ruleset_version"] = a.ruleset_version
    return d


@router.patch("/findings/{finding_id}/status")
def update_status(finding_id: str, body: FindingStatusUpdate, db: Session = Depends(get_db)):
    """Triage state only: never touches the captured evidence or the original observation."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    if f.status != body.status:
        db.add(FindingStatusHistory(finding_id=f.id, old_status=f.status, new_status=body.status, note=body.note))
        old, f.status = f.status, body.status
        db.commit()
        audit(db, "finding.status", f.id, old=old, new=body.status)
    return get_finding(finding_id, db)


@router.get("/evidence/{evidence_id}")
def evidence_detail(evidence_id: str, db: Session = Depends(get_db)):
    e = db.get(EvidenceRow, evidence_id)
    if not e:
        raise HTTPException(404, "Evidence not found")
    a = db.get(Analysis, e.analysis_id)
    f = db.get(Finding, e.finding_id)
    pkt = db.query(PacketMeta).filter_by(analysis_id=e.analysis_id, frame_number=e.frame).first() if e.frame else None
    sess = db.query(EmailSessionRow).filter_by(analysis_id=a.id, stream_id=e.stream_id).first() if e.stream_id is not None else None
    tls = db.query(TlsSessionRow).filter_by(analysis_id=a.id, stream_id=e.stream_id).first() if e.stream_id is not None else None
    return {"evidence": evidence_dict(e, a.capture.filename), "finding": finding_dict(f, capture_name=a.capture.filename, capture_id=a.capture_id),
            "packet": {"frame": pkt.frame_number, "tree": pkt.tree, "raw_hex": pkt.raw_hex, "protocol": pkt.protocol} if pkt else None,
            "session": session_dict(sess) if sess else None, "tls_session": tls_dict(tls) if tls else None,
            "capture": {"id": a.capture_id, "filename": a.capture.filename, "sha256": a.capture.sha256}, "analysis_id": a.id}
