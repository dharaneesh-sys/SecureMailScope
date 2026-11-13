"""SQLAlchemy models. Packet payloads are never stored; only metadata and sanitised observations."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Capture(Base):
    __tablename__ = "captures"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(200))
    stored_path: Mapped[str | None] = mapped_column(String(400))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    format: Mapped[str] = mapped_column(String(10))
    linktype: Mapped[str | None] = mapped_column(String(60))
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    authorised_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    retained: Mapped[bool] = mapped_column(Boolean, default=True)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="capture", cascade="all, delete-orphan")


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued running completed failed cancelled
    stage: Mapped[str | None] = mapped_column(String(40))
    progress: Mapped[int] = mapped_column(Integer, default=0)
    messages: Mapped[list] = mapped_column(JSON, default=list)
    counters: Mapped[dict] = mapped_column(JSON, default=dict)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    stage_log: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    failed_stage: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, index=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    ruleset_version: Mapped[str | None] = mapped_column(String(20))
    tool_info: Mapped[dict] = mapped_column(JSON, default=dict)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    engine_errors: Mapped[list] = mapped_column(JSON, default=list)
    ai_summary: Mapped[dict | None] = mapped_column(JSON)
    capture: Mapped[Capture] = relationship(back_populates="analyses")


class PacketMeta(Base):
    """Metadata only, for frames referenced by evidence or protocol events."""
    __tablename__ = "packets_metadata"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    frame_number: Mapped[int] = mapped_column(Integer)
    stream_id: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[float | None] = mapped_column(Float)
    direction: Mapped[str | None] = mapped_column(String(20))
    protocol: Mapped[str | None] = mapped_column(String(20))
    tree: Mapped[dict | None] = mapped_column(JSON)  # sanitised decoded field tree
    raw_hex: Mapped[str | None] = mapped_column(Text)  # TLS handshake frames only
    __table_args__ = (Index("ix_packets_analysis_frame", "analysis_id", "frame_number"),)


class TcpStreamRow(Base):
    __tablename__ = "tcp_streams"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    stream_id: Mapped[int] = mapped_column(Integer)
    client: Mapped[str] = mapped_column(String(80))
    server: Mapped[str] = mapped_column(String(80))
    protocol: Mapped[str | None] = mapped_column(String(10))
    detected_by: Mapped[str | None] = mapped_column(String(10))
    frames: Mapped[int] = mapped_column(Integer)
    first_ts: Mapped[float] = mapped_column(Float)
    last_ts: Mapped[float] = mapped_column(Float)
    completeness: Mapped[str] = mapped_column(String(12))
    quality: Mapped[dict] = mapped_column(JSON, default=dict)  # syn/fin/retransmissions/out_of_order/lost


class EmailSessionRow(Base):
    __tablename__ = "email_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    stream_id: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), index=True)
    client: Mapped[str] = mapped_column(String(80))
    server: Mapped[str] = mapped_column(String(80))
    first_ts: Mapped[float] = mapped_column(Float)
    last_ts: Mapped[float] = mapped_column(Float)
    banner: Mapped[str | None] = mapped_column(String(200))
    implicit_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_by: Mapped[str] = mapped_column(String(10))
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    starttls: Mapped[dict] = mapped_column(JSON, default=dict)  # offered / command / response / accepted / tls_followed
    events: Mapped[list] = mapped_column(JSON, default=list)
    states: Mapped[dict] = mapped_column(JSON, default=dict)  # observed / not_observed / incomplete / undecodable per item
    notes: Mapped[list] = mapped_column(JSON, default=list)
    completeness: Mapped[str] = mapped_column(String(12))


class TlsSessionRow(Base):
    __tablename__ = "tls_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    stream_id: Mapped[int] = mapped_column(Integer)
    carrier_protocol: Mapped[str | None] = mapped_column(String(12))
    via_starttls: Mapped[bool] = mapped_column(Boolean, default=False)
    client: Mapped[str] = mapped_column(String(80))
    server: Mapped[str] = mapped_column(String(80))
    record_versions: Mapped[list] = mapped_column(JSON, default=list)
    client_hello: Mapped[dict | None] = mapped_column(JSON)
    server_hello: Mapped[dict | None] = mapped_column(JSON)
    selected_version: Mapped[str | None] = mapped_column(String(20), index=True)
    selected_cipher: Mapped[str | None] = mapped_column(String(80), index=True)
    completeness: Mapped[str] = mapped_column(String(12))
    notes: Mapped[list] = mapped_column(JSON, default=list)
    flags: Mapped[dict] = mapped_column(JSON, default=dict)
    ciphers: Mapped[list["TlsCipherObservation"]] = relationship(cascade="all, delete-orphan")


class TlsCipherObservation(Base):
    __tablename__ = "tls_cipher_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tls_session_id: Mapped[int] = mapped_column(ForeignKey("tls_sessions.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    suite_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(10))  # offered | selected
    weak_class: Mapped[str | None] = mapped_column(String(10))
    forward_secret: Mapped[bool | None] = mapped_column(Boolean)


class CertificateRow(Base):
    __tablename__ = "certificates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    stream_id: Mapped[int] = mapped_column(Integer)
    position: Mapped[int] = mapped_column(Integer)
    frame: Mapped[int | None] = mapped_column(Integer)
    subject: Mapped[str] = mapped_column(String(400))
    issuer: Mapped[str] = mapped_column(String(400))
    serial: Mapped[str] = mapped_column(String(80))
    not_before: Mapped[str] = mapped_column(String(40))
    not_after: Mapped[str] = mapped_column(String(40))
    sig_algorithm: Mapped[str] = mapped_column(String(60))
    key_algorithm: Mapped[str] = mapped_column(String(40))
    key_size: Mapped[int | None] = mapped_column(Integer)
    san: Mapped[list] = mapped_column(JSON, default=list)
    sha256: Mapped[str] = mapped_column(String(64))
    self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    checks: Mapped[list] = mapped_column(JSON, default=list)  # per-check result at capture time


class SecurityRule(Base):
    __tablename__ = "security_rules"
    rule_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(10))
    description: Mapped[str] = mapped_column(Text)
    detection: Mapped[str] = mapped_column(Text)
    evidence_requirements: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    signature: Mapped[str] = mapped_column(String(20), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)
    enabled: Mapped[dict] = mapped_column(JSON)
    versions: Mapped[dict] = mapped_column(JSON)
    note: Mapped[str | None] = mapped_column(String(200))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    ref: Mapped[str] = mapped_column(String(20))  # human readable F-0001
    rule_id: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(240))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    category: Mapped[str] = mapped_column(String(60), index=True)
    protocol: Mapped[str | None] = mapped_column(String(12))
    stream_id: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text)
    technical: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    observation_type: Mapped[str] = mapped_column(String(24), index=True)
    completeness: Mapped[str] = mapped_column(String(12))
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    evidence: Mapped[list["EvidenceRow"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    history: Mapped[list["FindingStatusHistory"]] = relationship(cascade="all, delete-orphan", order_by="FindingStatusHistory.at")


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    ref: Mapped[str] = mapped_column(String(20))
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    frame: Mapped[int | None] = mapped_column(Integer)
    stream_id: Mapped[int | None] = mapped_column(Integer)
    direction: Mapped[str | None] = mapped_column(String(20))
    timestamp: Mapped[float | None] = mapped_column(Float)
    protocol: Mapped[str] = mapped_column(String(12))
    description: Mapped[str] = mapped_column(Text)
    fields: Mapped[dict] = mapped_column(JSON, default=dict)
    parser: Mapped[str] = mapped_column(String(40))
    completeness: Mapped[str] = mapped_column(String(12))
    finding: Mapped[Finding] = relationship(back_populates="evidence")


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    old_status: Mapped[str | None] = mapped_column(String(16))
    new_status: Mapped[str] = mapped_column(String(16))
    note: Mapped[str | None] = mapped_column(String(400))
    at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class GeneratedReport(Base):
    __tablename__ = "generated_reports"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(8))
    filename: Mapped[str] = mapped_column(String(200))
    path: Mapped[str] = mapped_column(String(400))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now)


class AppSetting(Base):
    __tablename__ = "application_settings"
    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime, default=_now, index=True)
    action: Mapped[str] = mapped_column(String(60))
    subject: Mapped[str | None] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
