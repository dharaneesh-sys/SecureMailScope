from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db
from app.models.tables import Analysis, AuditLog, Capture, CertificateRow, EmailSessionRow, Finding, SecurityRule, TlsCipherObservation, TlsSessionRow
from app.rules.registry import all_rules
from app.services import app_settings, tshark_runner
from app.services.audit import audit
from app.services.serializers import analysis_dict, finding_dict, iso

router = APIRouter()
STARTED = dt.datetime.now(dt.timezone.utc)


def latest_analysis_ids(db: Session) -> list[str]:
    """Most recent *completed* analysis per capture, so reruns never double-count."""
    rows = (db.query(Analysis.capture_id, func.max(Analysis.created_at)).filter(Analysis.status == "completed").group_by(Analysis.capture_id).all())
    ids = []
    for cid, ts in rows:
        a = db.query(Analysis.id).filter(Analysis.capture_id == cid, Analysis.created_at == ts, Analysis.status == "completed").first()
        if a:
            ids.append(a[0])
    return ids


@router.get("/health")
def health(db: Session = Depends(get_db)):
    info = tshark_runner.tool_info()
    return {"status": "ok", "version": "1.0.0", "started_at": STARTED.isoformat(timespec="seconds"), "tshark": info["available"], "database": "sqlite",
            "rules": len(all_rules()), "captures": db.query(Capture).count()}


@router.get("/system/dependencies")
def dependencies():
    info = tshark_runner.tool_info()
    return {"tshark": info, "python": __import__("sys").version.split()[0],
            "guidance": None if info["available"] else info.get("error"), "limits": {"max_upload_mb": settings.max_upload_mb, "analysis_timeout_s": settings.analysis_timeout_s, "max_packets": settings.max_packets}}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    ids = latest_analysis_ids(db)
    total_caps = db.query(Capture).count()
    done = db.query(Analysis).filter(Analysis.status == "completed").count()
    failed = db.query(Analysis).filter(Analysis.status == "failed").count()
    sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    over_time: dict[str, Counter] = {}
    findings_total = 0
    if ids:
        for s, n in db.query(Finding.severity, func.count()).filter(Finding.analysis_id.in_(ids)).group_by(Finding.severity):
            sev[s] = n
            findings_total += n
        for day, s, n in db.query(func.date(Finding.created_at), Finding.severity, func.count()).filter(Finding.analysis_id.in_(ids)).group_by(func.date(Finding.created_at), Finding.severity):
            over_time.setdefault(str(day), Counter())[s] += n
    proto = {p: n for p, n in db.query(EmailSessionRow.protocol, func.count()).filter(EmailSessionRow.analysis_id.in_(ids)).group_by(EmailSessionRow.protocol)} if ids else {}
    versions = {(v or "Unknown"): n for v, n in db.query(TlsSessionRow.selected_version, func.count()).filter(TlsSessionRow.analysis_id.in_(ids)).group_by(TlsSessionRow.selected_version)} if ids else {}
    ciphers = {c: n for c, n in db.query(TlsCipherObservation.name, func.count()).filter(TlsCipherObservation.analysis_id.in_(ids), TlsCipherObservation.role == "selected").group_by(TlsCipherObservation.name)} if ids else {}
    recent = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(8).all()
    recent_f = db.query(Finding).filter(Finding.analysis_id.in_(ids), Finding.severity != "info").order_by(Finding.created_at.desc(), Finding.risk_score.desc()).limit(8).all() if ids else []
    amap = {a.id: a for a in db.query(Analysis).filter(Analysis.id.in_({f.analysis_id for f in recent_f}))} if recent_f else {}
    return {
        "metrics": {"captures": total_caps, "analyses_completed": done, "email_sessions": db.query(EmailSessionRow).filter(EmailSessionRow.analysis_id.in_(ids)).count() if ids else 0,
                    "findings": findings_total, "critical_high": sev["critical"] + sev["high"], "tls_sessions": db.query(TlsSessionRow).filter(TlsSessionRow.analysis_id.in_(ids)).count() if ids else 0,
                    "success_rate": round(100 * done / (done + failed), 1) if (done + failed) else None, "certificates": db.query(CertificateRow).filter(CertificateRow.analysis_id.in_(ids)).count() if ids else 0},
        "severity": sev, "findings_over_time": [{"date": d, **{s: c.get(s, 0) for s in sev}} for d, c in sorted(over_time.items())],
        "protocols": [{"name": k.upper(), "value": v} for k, v in proto.items()], "tls_versions": [{"name": k, "value": v} for k, v in versions.items()],
        "ciphers": [{"name": k, "value": v} for k, v in sorted(ciphers.items(), key=lambda x: -x[1])],
        "recent_analyses": [analysis_dict(a, db) for a in recent],
        "recent_findings": [finding_dict(f, capture_name=amap[f.analysis_id].capture.filename, capture_id=amap[f.analysis_id].capture_id) for f in recent_f],
        "demo_loaded": db.query(Capture).filter(Capture.is_demo.is_(True)).count() > 0,
    }


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    return {"settings": app_settings.get_all(db), "env": {"data_dir": str(settings.data_dir), "tshark_path": tshark_runner.find_tshark(), "max_upload_mb_cap": settings.max_upload_mb,
                                                          "ai_api_key_configured": bool(settings.ai_api_key)}}


@router.put("/settings")
def put_settings(patch: dict, db: Session = Depends(get_db)):
    try:
        new = app_settings.update(db, patch)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, "settings.updated", None, keys=sorted(patch))
    return {"settings": new}


@router.get("/system/logs")
def logs(lines: int = Query(200, ge=1, le=2000)):
    p = settings.data_dir / "app.log"
    if not p.exists():
        return {"lines": []}
    return {"lines": p.read_text(errors="replace").splitlines()[-lines:]}


@router.get("/system/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return {"items": [{"id": r.id, "at": iso(r.at), "action": r.action, "subject": r.subject, "detail": r.detail} for r in rows]}


@router.post("/system/retention/run")
def run_retention(db: Session = Depends(get_db)):
    return apply_retention(db)


def apply_retention(db: Session) -> dict:
    days = app_settings.get(db, "retention_days")
    removed = 0
    if days > 0:
        cutoff = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=days)
        for c in db.query(Capture).filter(Capture.uploaded_at < cutoff, Capture.retained.is_(True), Capture.is_demo.is_(False)):
            if c.stored_path:
                Path(c.stored_path).unlink(missing_ok=True)
            c.retained = False
            removed += 1
        db.commit()
    audit(db, "retention.run", None, original_captures_removed=removed, retention_days=days)
    return {"original_captures_removed": removed, "retention_days": days}
