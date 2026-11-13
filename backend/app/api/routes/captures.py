from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import ensure_within, sanitize_filename
from app.database.session import get_db
from app.models.tables import Analysis, Capture, GeneratedReport
from app.services import app_settings
from app.services.audit import audit
from app.services.capture_service import CaptureRejected, sha256_file, validate_capture
from app.services.serializers import capture_dict

router = APIRouter()
ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}


def _summaries(db: Session, caps: list[Capture]) -> list[dict]:
    out = []
    for c in caps:
        latest = db.query(Analysis).filter(Analysis.capture_id == c.id).order_by(Analysis.created_at.desc()).first()
        d = capture_dict(c)
        d["latest_analysis"] = None
        if latest:
            from app.services.serializers import analysis_dict
            ld = analysis_dict(latest, db)
            d["latest_analysis"] = {"id": latest.id, "status": latest.status, "findings": latest.counters.get("findings", 0), "highest_severity": ld["highest_severity"], "protocols": ld["protocols"]}
        d["analysis_count"] = db.query(Analysis).filter(Analysis.capture_id == c.id).count()
        out.append(d)
    return out


@router.post("/captures", status_code=201)
async def upload_capture(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload + content validation + hashing. Does NOT start analysis (that needs the authorisation confirmation)."""
    name = sanitize_filename(file.filename or "capture.pcap")
    if Path(name).suffix.lower() not in ALLOWED_EXT:
        raise HTTPException(415, "Only .pcap, .pcapng (or .cap) files are accepted.")
    limit = app_settings.get(db, "max_upload_mb") * 1024 * 1024
    settings.ensure_dirs()
    cid = uuid.uuid4().hex
    dest = ensure_within(settings.uploads_dir, settings.uploads_dir / f"{cid}.upload")
    size = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"File exceeds the {limit // (1024 * 1024)} MB upload limit.")
                out.write(chunk)
        try:
            meta = validate_capture(dest)
        except CaptureRejected as exc:
            audit(db, "capture.rejected", name, code=exc.code)
            raise HTTPException(422, {"code": exc.code, "message": exc.message}) from exc
        digest = sha256_file(dest)
        dup = db.query(Capture).filter(Capture.sha256 == digest).first()
        if dup:
            dest.unlink(missing_ok=True)
            return {"capture": _summaries(db, [dup])[0], "duplicate": True, "message": f"An identical capture was already uploaded as '{dup.filename}'. The existing record is being reused."}
        final = dest.with_name(f"{cid}.{meta.format}")
        dest.rename(final)
        cap = Capture(id=cid, filename=name, stored_path=str(final), sha256=digest, size_bytes=size, format=meta.format, linktype=meta.linktype_name,
                      packet_count=meta.packet_count, warnings=meta.warnings)
        db.add(cap)
        db.commit()
        audit(db, "capture.uploaded", cid, filename=name, sha256=digest, size=size)
        return {"capture": _summaries(db, [cap])[0], "duplicate": False, "message": "Capture validated."}
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    except Exception:
        dest.unlink(missing_ok=True)
        raise


@router.get("/captures")
def list_captures(q: str | None = None, sort: str = Query("uploaded_at"), order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200), db: Session = Depends(get_db)):
    query = db.query(Capture)
    if q:
        like = f"%{q.strip()[:80]}%"
        query = query.filter((Capture.filename.ilike(like)) | (Capture.sha256.ilike(like)))
    col = {"uploaded_at": Capture.uploaded_at, "filename": Capture.filename, "size": Capture.size_bytes, "packets": Capture.packet_count}.get(sort, Capture.uploaded_at)
    query = query.order_by(col.desc() if order == "desc" else col.asc())
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": _summaries(db, rows), "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


@router.get("/captures/{capture_id}")
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    c = db.get(Capture, capture_id)
    if not c:
        raise HTTPException(404, "Capture not found")
    return _summaries(db, [c])[0]


@router.get("/captures/{capture_id}/download")
def download_capture(capture_id: str, db: Session = Depends(get_db)):
    from fastapi.responses import FileResponse
    c = db.get(Capture, capture_id)
    if not c:
        raise HTTPException(404, "Capture not found")
    if not c.retained or not c.stored_path or not Path(c.stored_path).exists():
        raise HTTPException(410, "The original capture is no longer retained (retention policy).")
    return FileResponse(c.stored_path, filename=c.filename, media_type="application/vnd.tcpdump.pcap")


@router.delete("/captures/{capture_id}")
def delete_capture(capture_id: str, db: Session = Depends(get_db)):
    c = db.get(Capture, capture_id)
    if not c:
        raise HTTPException(404, "Capture not found")
    for r in db.query(GeneratedReport).join(Analysis, GeneratedReport.analysis_id == Analysis.id).filter(Analysis.capture_id == capture_id):
        Path(r.path).unlink(missing_ok=True)
    if c.stored_path:
        Path(c.stored_path).unlink(missing_ok=True)
    name, sha = c.filename, c.sha256
    db.delete(c)
    db.commit()
    audit(db, "capture.deleted", capture_id, filename=name, sha256=sha)
    return {"deleted": capture_id}


@router.get("/demo/status")
def demo_status(db: Session = Depends(get_db)):
    manifest = settings.demo_dir / "manifest.json"
    avail = [n for n, e in json.loads(manifest.read_text())["valid"].items() if e.get("demo")] if manifest.exists() else []
    return {"available": avail, "loaded": db.query(Capture).filter(Capture.is_demo.is_(True)).count(),
            "label": "CONTROLLED SYNTHETIC DEMONSTRATION DATA - NOT REAL CUSTOMER TRAFFIC."}


@router.post("/demo/load", status_code=201)
def load_demo(db: Session = Depends(get_db)):
    from app.workers import pipeline
    manifest = settings.demo_dir / "manifest.json"
    if not manifest.exists():
        raise HTTPException(404, "Demo dataset not found (sample_data/authorised_demo_captures).")
    created = []
    for name, exp in json.loads(manifest.read_text())["valid"].items():
        if not exp.get("demo"):
            continue
        src = settings.demo_dir / name
        digest = sha256_file(src)
        if db.query(Capture).filter(Capture.sha256 == digest).first():
            continue
        meta = validate_capture(src)
        cid = uuid.uuid4().hex
        dest = settings.uploads_dir / f"{cid}.{meta.format}"
        shutil.copyfile(src, dest)
        cap = Capture(id=cid, filename=name, stored_path=str(dest), sha256=digest, size_bytes=dest.stat().st_size, format=meta.format, linktype=meta.linktype_name,
                      packet_count=meta.packet_count, is_demo=True, authorised_confirmed=True, warnings=[])
        db.add(cap)
        db.flush()
        a = Analysis(capture_id=cid, status="queued", options={"authorised_by": "synthetic demo dataset", "generate_report": True})
        db.add(a)
        db.commit()
        pipeline.submit(a.id)
        created.append({"capture_id": cid, "analysis_id": a.id, "filename": name})
    audit(db, "demo.loaded", None, count=len(created))
    return {"created": created, "label": "CONTROLLED SYNTHETIC DEMONSTRATION DATA - NOT REAL CUSTOMER TRAFFIC."}


@router.delete("/demo")
def remove_demo(db: Session = Depends(get_db)):
    n = 0
    for c in db.query(Capture).filter(Capture.is_demo.is_(True)).all():
        delete_capture(c.id, db)
        n += 1
    return {"removed": n}
