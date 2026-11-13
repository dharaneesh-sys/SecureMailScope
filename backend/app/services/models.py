"""Plain dataclasses passed between the analysis stages (no DB coupling)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceRef:
    """A pointer to concrete parsed data supporting an observation or finding."""

    frame: int | None
    stream: int | None
    direction: str | None  # client->server | server->client
    timestamp: float | None
    protocol: str
    description: str
    fields: dict[str, Any] = field(default_factory=dict)
    parser: str = "tshark"
    completeness: str = "complete"  # complete | partial | incomplete


@dataclass
class StreamInfo:
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    first_ts: float
    last_ts: float
    frames: int = 0
    payload_frames: int = 0
    syn: bool = False
    synack: bool = False
    fin: bool = False
    rst: bool = False
    retransmissions: int = 0
    out_of_order: int = 0
    lost_segments: int = 0
    protocol: str | None = None
    detected_by: str | None = None  # port | banner | both
    implicit_tls: bool = False

    @property
    def completeness(self) -> str:
        if self.lost_segments:
            return "partial"
        if self.syn and (self.fin or self.rst):
            return "complete"
        if self.syn:
            return "partial"
        return "partial"


@dataclass
class ProtoEvent:
    frame: int
    stream: int
    ts: float
    direction: str  # client->server | server->client
    kind: str  # greeting | command | response | capability | tls_transition | note
    verb: str
    summary: str
    state: str = "observed"  # observed | not_observed | incomplete | undecodable


@dataclass
class EmailSessionObs:
    stream_id: int
    protocol: str  # smtp | imap | pop3
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    first_ts: float
    last_ts: float
    events: list[ProtoEvent] = field(default_factory=list)
    detected_by: str = "port"
    implicit_tls: bool = False
    banner: str | None = None
    capabilities: list[str] = field(default_factory=list)
    starttls_offered: bool | None = None  # None -> capability list not observed
    starttls_command: ProtoEvent | None = None
    starttls_response: ProtoEvent | None = None
    starttls_accepted: bool | None = None
    tls_after_starttls: bool = False
    auth_events: list[ProtoEvent] = field(default_factory=list)  # cleartext auth observed
    plaintext_transaction: list[ProtoEvent] = field(default_factory=list)  # MAIL/RCPT/DATA etc. in cleartext
    stream_completeness: str = "partial"
    notes: list[str] = field(default_factory=list)


@dataclass
class CertObs:
    stream_id: int
    position: int  # 0 = leaf
    frame: int | None
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    sig_algorithm: str
    sig_hash: str | None
    key_algorithm: str
    key_size: int | None
    san: list[str]
    sha256: str
    self_signed: bool
    is_ca: bool | None
    der_len: int
    ts: float | None = None


@dataclass
class TlsSessionObs:
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    carrier_protocol: str | None  # smtp/imap/pop3/tls-direct
    via_starttls: bool
    first_ts: float | None = None
    record_versions: list[str] = field(default_factory=list)
    client_hello_frame: int | None = None
    client_hello_ts: float | None = None
    client_legacy_version: int | None = None
    client_supported_versions: list[int] = field(default_factory=list)
    offered_ciphers: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_groups: list[str] = field(default_factory=list)
    signature_algorithms: list[str] = field(default_factory=list)
    extensions_offered: list[int] = field(default_factory=list)
    ech_seen: bool = False
    server_hello_frame: int | None = None
    server_hello_ts: float | None = None
    server_legacy_version: int | None = None
    selected_version: int | None = None
    selected_version_source: str | None = None  # supported_versions | server_version
    selected_cipher: int | None = None
    server_extensions: list[int] = field(default_factory=list)
    certificate_frame: int | None = None
    certificates: list[CertObs] = field(default_factory=list)
    server_hello_done: bool = False
    server_key_exchange: bool = False
    change_cipher_spec_seen: bool = False
    encrypted_after_hello: bool = False  # application data / encrypted handshake observed
    alerts: list[str] = field(default_factory=list)
    frames: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def tls13(self) -> bool:
        return self.selected_version == 0x0304

    @property
    def completeness(self) -> str:
        if self.client_hello_frame and self.server_hello_frame:
            if self.tls13 or self.server_hello_done or self.certificate_frame:
                return "complete"
            return "partial"
        return "incomplete"


@dataclass
class AnalysisContext:
    """Everything the rule engine may look at."""

    capture_name: str
    capture_start_ts: float | None
    sessions: list[EmailSessionObs]
    tls_sessions: list[TlsSessionObs]
    streams: list[StreamInfo]
    evidence_index: dict[str, EvidenceRef] = field(default_factory=dict)
    cert_reference_ts: float | None = None  # time used for validity checks
    cert_reference: str = "capture"
