from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_analysis_or_404
from app.database.session import get_db
from app.models.tables import Analysis, Capture, CertificateRow, EmailSessionRow, EvidenceRow, Finding, TcpStreamRow, TlsSessionRow
from app.schemas.api import AnalysisCreate
from app.services import tshark_runner as tsr
from app.services.audit import audit
from app.services.engine import STAGES
from app.services.serializers import (analysis_dict, cert_dict, evidence_dict, session_dict, stream_dict, summary_dict, tls_dict)
from app.workers import pipeline

router = APIRouter()


def _start(db: Session, cap: Capture, options: dict) -> Analysis:
    if not cap.retained or not cap.stored_path or not Path(cap.stored_path).exists():
        raise HTTPException(410, "The original capture file is no longer retained, so it cannot be analysed again. Upload it again.")
    a = Analysis(capture_id=cap.id, status="queued", options=options)
    db.add(a)
    cap.authorised_confirmed = True
    db.commit()
    audit(db, "analysis.created", a.id, capture=cap.id, authorised_confirmation=True)
    pipeline.submit(a.id)
    return a


@router.post("/analyses", status_code=202)
def create_analysis(body: AnalysisCreate, db: Session = Depends(get_db)):
    if not body.authorised_confirmation:
        raise HTTPException(422, "You must confirm that the capture was obtained from a system or network you are authorised to analyse.")
    cap = db.get(Capture, body.capture_id)
    if not cap:
        raise HTTPException(404, "Capture not found")
    info = tsr.tool_info()
    if not info["available"]:
        raise HTTPException(503, {"code": "tshark_missing", "message": info.get("error")})
    a = _start(db, cap, body.options.model_dump())
    return analysis_dict(a, db)


@router.get("/analyses")
def list_analyses(status: str | None = None, capture_id: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200), db: Session = Depends(get_db)):
    q = db.query(Analysis)
    if status:
        q = q.filter(Analysis.status == status)
    if capture_id:
        q = q.filter(Analysis.capture_id == capture_id)
    q = q.order_by(Analysis.created_at.desc())
    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [analysis_dict(a, db) for a in rows], "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


@router.get("/analyses/{analysis_id}")
def get_analysis(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    return {**analysis_dict(a, db), "limitations": a.limitations, "engine_errors": a.engine_errors, "tool": a.tool_info, "ai_summary": a.ai_summary}


@router.get("/analyses/{analysis_id}/status")
def analysis_status(a: Analysis = Depends(get_analysis_or_404)):
    return {"id": a.id, "status": a.status, "stage": a.stage, "progress": a.progress, "counters": a.counters, "messages": a.messages[-30:], "stage_log": a.stage_log,
            "error": a.error, "failed_stage": a.failed_stage, "stages": [{"key": k, "label": v} for k, v in STAGES]}


@router.post("/analyses/{analysis_id}/cancel")
def cancel_analysis(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    if a.status not in ("queued", "running"):
        raise HTTPException(409, f"Analysis is already {a.status}.")
    tsr.request_cancel(a.id)
    if a.status == "queued":
        a.status = "cancelled"
        db.commit()
    return {"id": a.id, "status": "cancelling" if a.status == "running" else a.status}


@router.post("/analyses/{analysis_id}/rerun", status_code=202)
def rerun(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    cap = db.get(Capture, a.capture_id)
    return analysis_dict(_start(db, cap, a.options or {}), db)


def _done(a: Analysis) -> Analysis:
    if a.status != "completed":
        raise HTTPException(409, f"Analysis is {a.status}; results are available once it has completed.")
    return a


@router.get("/analyses/{analysis_id}/summary")
def summary(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    return summary_dict(db, _done(a))


@router.get("/analyses/{analysis_id}/protocols")
def protocols(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    _done(a)
    return {"sessions": [session_dict(s) for s in db.query(EmailSessionRow).filter_by(analysis_id=a.id).order_by(EmailSessionRow.stream_id)],
            "streams": [stream_dict(s) for s in db.query(TcpStreamRow).filter_by(analysis_id=a.id).order_by(TcpStreamRow.stream_id)]}


@router.get("/analyses/{analysis_id}/tls")
def tls(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    _done(a)
    return {"sessions": [tls_dict(t) for t in db.query(TlsSessionRow).filter_by(analysis_id=a.id).order_by(TlsSessionRow.stream_id)]}


@router.get("/analyses/{analysis_id}/certificates")
def certificates(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    _done(a)
    tls_rows = db.query(TlsSessionRow).filter_by(analysis_id=a.id).all()
    unavailable = [{"stream_id": t.stream_id, "reason": ("TLS 1.3: the Certificate message is encrypted after the ServerHello" if t.flags.get("tls13")
                    else "No Certificate message in the captured handshake (resumption or truncated capture)" if t.server_hello else "No ServerHello observed")}
                   for t in tls_rows if not t.flags.get("certificate_visible")]
    return {"certificates": [cert_dict(c) for c in db.query(CertificateRow).filter_by(analysis_id=a.id).order_by(CertificateRow.stream_id, CertificateRow.position)],
            "unavailable": unavailable, "notice": "Certificate metadata was extracted from the capture. Trust-chain and revocation validation were NOT performed."}


@router.get("/analyses/{analysis_id}/evidence")
def evidence(a: Analysis = Depends(get_analysis_or_404), finding_id: str | None = None, protocol: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    _done(a)
    q = db.query(EvidenceRow).filter(EvidenceRow.analysis_id == a.id)
    if finding_id:
        q = q.filter(EvidenceRow.finding_id == finding_id)
    if protocol:
        q = q.filter(EvidenceRow.protocol == protocol.upper())
    q = q.order_by(EvidenceRow.ref)
    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    fin = {f.id: f for f in db.query(Finding).filter(Finding.analysis_id == a.id)}
    items = []
    for e in rows:
        d = evidence_dict(e, a.capture.filename)
        f = fin.get(e.finding_id)
        d["finding"] = {"id": f.id, "ref": f.ref, "title": f.title, "severity": f.severity, "rule_id": f.rule_id} if f else None
        items.append(d)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}
