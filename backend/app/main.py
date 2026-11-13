"""SecureMailScope API entrypoint."""

from __future__ import annotations

import datetime as dt
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import analyses, captures, findings, reports, rules, system
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.database.session import SessionLocal, init_db
from app.models.tables import Analysis
from app.services import rules_sync, tshark_runner


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    log = get_logger()
    settings.ensure_dirs()
    init_db()
    db = SessionLocal()
    try:
        rules_sync.sync_rules(db)
        stale = db.query(Analysis).filter(Analysis.status.in_(("queued", "running"))).all()
        for a in stale:  # jobs die with the process; never leave them looking alive
            a.status, a.error = "failed", "Interrupted by an application restart."
            a.finished_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        db.commit()
        system.apply_retention(db)
    finally:
        db.close()
    info = tshark_runner.tool_info()
    log.info("SecureMailScope started; TShark: %s", info.get("version") or "NOT FOUND")
    yield


app = FastAPI(title="SecureMailScope API", version="1.0.0", lifespan=lifespan,
              description="Passive, evidence-linked email cryptographic security posture assessment from authorised PCAP files.")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    get_logger().exception("unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


for r in (system.router, captures.router, analyses.router, findings.router, rules.router, reports.router):
    app.include_router(r, prefix="/api")
