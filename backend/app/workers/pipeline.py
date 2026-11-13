"""Background analysis worker (thread pool). Progress is written to the DB as real work completes."""

from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.database.session import SessionLocal
from app.models.tables import Analysis, Capture
from app.services import app_settings, report_service, rules_sync, tshark_runner as tsr
from app.services.audit import audit
from app.services.capture_service import CaptureRejected
from app.services.engine import STAGES, run_engine
from app.services.persistence import persist_result

log = get_logger("worker")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sms-analysis")
_STAGE_INDEX = {k: i for i, (k, _) in enumerate(STAGES)}
_LABEL = dict(STAGES)


def submit(analysis_id: str) -> None:
    _executor.submit(run_analysis, analysis_id)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def run_analysis(analysis_id: str) -> None:
    db = SessionLocal()
    try:
        a = db.get(Analysis, analysis_id)
        if a is None:
            return
        cap = db.get(Capture, a.capture_id)
        a.status, a.started_at, a.messages, a.stage_log = "running", _now(), [], []
        db.commit()
        tsr.clear_cancel(analysis_id)

        def progress(stage: str, message: str, counters: dict | None) -> None:
            if tsr.is_cancelled(analysis_id):
                raise tsr.AnalysisCancelled()
            idx = _STAGE_INDEX[stage]
            log_ = [dict(x) for x in a.stage_log]
            for x in log_:
                if x["status"] == "running" and x["key"] != stage:
                    x["status"] = "done"
            entry = next((x for x in log_ if x["key"] == stage), None)
            if entry is None:
                entry = {"key": stage, "label": _LABEL[stage], "status": "running", "started_at": _now().isoformat(timespec="seconds")}
                log_.append(entry)
            entry["message"] = message
            a.stage_log = log_
            a.stage = stage
            a.progress = round(100 * idx / len(STAGES))
            a.messages = [*a.messages[-80:], {"t": _now().isoformat(timespec="seconds"), "stage": stage, "message": message}]
            if counters:
                a.counters = dict(counters)
            db.commit()

        try:
            cfg = app_settings.get_all(db)
            enabled = {rid for rid, on in rules_sync.enabled_map(db).items() if on}
            sig = rules_sync.current_signature(db)
            result = run_engine(Path(cap.stored_path), cap.filename, analysis_id=analysis_id, enabled_rules=enabled, progress=progress,
                                cert_reference=cfg["cert_reference"], options=a.options)
            persist_result(db, a, result, sig)
            progress("report_generation", "Generating JSON and HTML reports from stored results", None)
            if (a.options or {}).get("generate_report", True):
                for fmt in ("json", "html"):
                    report_service.generate(db, analysis_id, fmt)
            if cfg["ai_provider"] != "none":
                try:
                    from app.ai.explanation_service import generate_ai_summary
                    from app.services.serializers import finding_dict
                    from app.models.tables import Finding
                    fds = [finding_dict(f) for f in db.query(Finding).filter_by(analysis_id=analysis_id)]
                    a.ai_summary = generate_ai_summary(cfg, fds, settings.ai_api_key)
                except Exception as exc:  # AI is optional: never fail the analysis because of it
                    a.ai_summary = {"status": "error", "error": str(exc)}
            a.stage_log = [{**x, "status": "done"} for x in a.stage_log]
            a.status, a.progress, a.finished_at = "completed", 100, _now()
            db.commit()
            if not cfg["retain_original_captures"]:
                Path(cap.stored_path).unlink(missing_ok=True)
                cap.retained = False
                db.commit()
            audit(db, "analysis.completed", analysis_id, findings=a.counters.get("findings"))
        except tsr.AnalysisCancelled:
            db.rollback()
            a = db.get(Analysis, analysis_id)
            a.status, a.finished_at = "cancelled", _now()
            a.error = "Cancelled by the analyst."
            db.commit()
            audit(db, "analysis.cancelled", analysis_id)
        except Exception as exc:
            db.rollback()
            a = db.get(Analysis, analysis_id)
            msg = exc.message if isinstance(exc, CaptureRejected) else str(exc)
            log.exception("analysis %s failed", analysis_id)
            a.status, a.error, a.finished_at, a.failed_stage = "failed", msg, _now(), a.stage
            a.stage_log = [{**x, "status": "failed" if x["key"] == a.stage else x["status"]} for x in a.stage_log]
            db.commit()
            audit(db, "analysis.failed", analysis_id, stage=a.stage, error=msg[:200])
    finally:
        db.close()
