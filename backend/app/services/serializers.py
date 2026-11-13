"""ORM -> JSON dict converters shared by the API and report generator."""

from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from app.models.tables import (Analysis, CertificateRow, EmailSessionRow, EvidenceRow, Finding, TcpStreamRow, TlsSessionRow)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def iso(d: dt.datetime | None) -> str | None:
    return d.replace(tzinfo=dt.timezone.utc).isoformat(timespec="seconds") if d else None


def ts_iso(ts: float | None) -> str | None:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="milliseconds") if ts else None


def capture_dict(c) -> dict:
    return {"id": c.id, "filename": c.filename, "sha256": c.sha256, "size_bytes": c.size_bytes, "format": c.format, "linktype": c.linktype,
            "packet_count": c.packet_count, "uploaded_at": iso(c.uploaded_at), "is_demo": c.is_demo, "retained": c.retained, "warnings": c.warnings}


def evidence_dict(e: EvidenceRow, capture_name: str | None = None) -> dict:
    return {"id": e.id, "ref": e.ref, "analysis_id": e.analysis_id, "finding_id": e.finding_id, "capture": capture_name, "frame": e.frame, "stream_id": e.stream_id,
            "direction": e.direction, "timestamp": ts_iso(e.timestamp), "protocol": e.protocol, "description": e.description, "fields": e.fields, "parser": e.parser,
            "completeness": e.completeness}


def finding_dict(f: Finding, with_evidence: bool = False, capture_name: str | None = None, capture_id: str | None = None) -> dict:
    d = {"id": f.id, "ref": f.ref, "analysis_id": f.analysis_id, "capture": capture_name, "capture_id": capture_id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
         "category": f.category, "protocol": f.protocol, "stream_id": f.stream_id, "description": f.description, "technical": f.technical, "impact": f.impact,
         "remediation": f.remediation, "observation_type": f.observation_type, "completeness": f.completeness, "risk_score": f.risk_score, "risk": f.risk,
         "status": f.status, "created_at": iso(f.created_at), "rule_version": f.rule_version, "evidence_count": len(f.evidence)}
    if with_evidence:
        d["evidence"] = [evidence_dict(e, capture_name) for e in f.evidence]
        d["history"] = [{"old_status": h.old_status, "new_status": h.new_status, "note": h.note, "at": iso(h.at)} for h in f.history]
    return d


def analysis_dict(a: Analysis, db: Session | None = None) -> dict:
    sev = None
    if db is not None:
        sevs = [s for (s,) in db.query(Finding.severity).filter(Finding.analysis_id == a.id).all()]
        order = [s for s in ("critical", "high", "medium", "low") if s in sevs]
        sev = order[0] if order else ("info" if sevs else None)
    return {"id": a.id, "capture_id": a.capture_id, "capture": capture_dict(a.capture) if a.capture else None, "status": a.status, "stage": a.stage, "progress": a.progress,
            "counters": a.counters, "messages": a.messages[-40:], "stage_log": a.stage_log, "error": a.error, "failed_stage": a.failed_stage, "created_at": iso(a.created_at),
            "started_at": iso(a.started_at), "finished_at": iso(a.finished_at), "ruleset_version": a.ruleset_version, "options": a.options, "highest_severity": sev,
            "protocols": sorted({s for (s,) in db.query(EmailSessionRow.protocol).filter(EmailSessionRow.analysis_id == a.id).distinct().all()}) if db is not None else []}


def session_dict(s: EmailSessionRow) -> dict:
    return {"stream_id": s.stream_id, "protocol": s.protocol, "client": s.client, "server": s.server, "first_ts": ts_iso(s.first_ts), "last_ts": ts_iso(s.last_ts), "banner": s.banner,
            "implicit_tls": s.implicit_tls, "detected_by": s.detected_by, "capabilities": s.capabilities, "starttls": s.starttls,
            "events": [{**e, "ts": ts_iso(e["ts"])} for e in s.events], "states": s.states, "notes": s.notes, "completeness": s.completeness}


def tls_dict(t: TlsSessionRow) -> dict:
    ch, sh = t.client_hello, t.server_hello
    return {"stream_id": t.stream_id, "carrier_protocol": t.carrier_protocol, "via_starttls": t.via_starttls, "client": t.client, "server": t.server,
            "record_versions": t.record_versions, "client_hello": {**ch, "ts": ts_iso(ch["ts"])} if ch else None, "server_hello": {**sh, "ts": ts_iso(sh["ts"])} if sh else None,
            "selected_version": t.selected_version, "selected_cipher": t.selected_cipher, "completeness": t.completeness, "notes": t.notes, "flags": t.flags}


def cert_dict(c: CertificateRow) -> dict:
    return {"id": c.id, "stream_id": c.stream_id, "position": c.position, "frame": c.frame, "subject": c.subject, "issuer": c.issuer, "serial": c.serial, "not_before": c.not_before,
            "not_after": c.not_after, "sig_algorithm": c.sig_algorithm, "key_algorithm": c.key_algorithm, "key_size": c.key_size, "san": c.san, "sha256": c.sha256,
            "self_signed": c.self_signed, "checks": c.checks}


def stream_dict(s: TcpStreamRow) -> dict:
    return {"stream_id": s.stream_id, "client": s.client, "server": s.server, "protocol": s.protocol, "detected_by": s.detected_by, "frames": s.frames,
            "first_ts": ts_iso(s.first_ts), "last_ts": ts_iso(s.last_ts), "completeness": s.completeness, "quality": s.quality}


def summary_dict(db: Session, a: Analysis) -> dict:
    findings = db.query(Finding).filter(Finding.analysis_id == a.id).all()
    sev = {s: 0 for s in SEV_ORDER}
    status = {}
    obs = {}
    for f in findings:
        sev[f.severity] += 1
        status[f.status] = status.get(f.status, 0) + 1
        obs[f.observation_type] = obs.get(f.observation_type, 0) + 1
    tls = db.query(TlsSessionRow).filter(TlsSessionRow.analysis_id == a.id).all()
    versions: dict[str, int] = {}
    for t in tls:
        versions[t.selected_version or "Unknown (no ServerHello)"] = versions.get(t.selected_version or "Unknown (no ServerHello)", 0) + 1
    return {"analysis": analysis_dict(a, db), "counters": a.counters, "severity": sev, "status": status, "observation_types": obs, "tls_versions": versions,
            "limitations": a.limitations, "engine_errors": a.engine_errors, "tool": a.tool_info,
            "certificates_observed": db.query(CertificateRow).filter(CertificateRow.analysis_id == a.id).count()}
