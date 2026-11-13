from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_analysis_or_404
from app.core.security import ensure_within
from app.core.config import settings
from app.database.session import get_db
from app.models.tables import Analysis, GeneratedReport
from app.schemas.api import ReportCreate
from app.services import report_service
from app.services.audit import audit
from app.services.serializers import iso

router = APIRouter()
CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"


def _rep(r: GeneratedReport, db: Session) -> dict:
    a = db.get(Analysis, r.analysis_id)
    return {"id": r.id, "analysis_id": r.analysis_id, "capture": a.capture.filename if a else None, "format": r.format, "filename": r.filename, "size_bytes": r.size_bytes,
            "sha256": r.sha256, "created_at": iso(r.created_at)}


@router.post("/analyses/{analysis_id}/reports", status_code=201)
def create_report(body: ReportCreate, a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    if a.status != "completed":
        raise HTTPException(409, f"Analysis is {a.status}; reports need a completed analysis.")
    row = report_service.generate(db, a.id, body.format)
    audit(db, "report.generated", row.id, format=body.format, analysis=a.id)
    return _rep(row, db)


@router.get("/analyses/{analysis_id}/report-preview")
def preview(a: Analysis = Depends(get_analysis_or_404), db: Session = Depends(get_db)):
    if a.status != "completed":
        raise HTTPException(409, "Preview needs a completed analysis.")
    html = report_service.render_html(report_service.build_report_data(db, a.id))
    return Response(html, media_type="text/html; charset=utf-8", headers={"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff"})


@router.get("/reports")
def list_reports(analysis_id: str | None = None, format: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200), db: Session = Depends(get_db)):
    q = db.query(GeneratedReport)
    if analysis_id:
        q = q.filter(GeneratedReport.analysis_id == analysis_id)
    if format:
        q = q.filter(GeneratedReport.format == format)
    q = q.order_by(GeneratedReport.created_at.desc())
    total = q.count()
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_rep(r, db) for r in rows], "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


@router.get("/reports/{report_id}/download")
def download(report_id: str, inline: bool = False, db: Session = Depends(get_db)):
    r = db.get(GeneratedReport, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    try:
        path = ensure_within(settings.reports_path, Path(r.path))
    except ValueError:
        raise HTTPException(403, "Report path is outside the reports directory") from None
    if not path.exists():
        raise HTTPException(410, "The report file is no longer on disk; generate it again.")
    headers = {"X-Content-Type-Options": "nosniff"}
    if r.format == "html":
        headers["Content-Security-Policy"] = CSP
    return FileResponse(path, media_type=report_service.MIME[r.format], filename=r.filename,
                        content_disposition_type="inline" if (inline and r.format == "html") else "attachment", headers=headers)
