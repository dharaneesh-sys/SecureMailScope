"""Analysis engine: PCAP in, structured observations + findings out.

Database-free on purpose so it can be unit-tested directly. The worker
(`app.workers.pipeline`) persists the :class:`EngineResult`.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.core.config import settings
from app.core.logging import get_logger
from app.rules.base import FindingDraft, session_for
from app.rules.registry import all_rules

from . import tshark_runner as tsr
from .capture_service import CaptureMeta, validate_capture
from .email_common import EmailAnalyzer
from .frames import FrameMeta, frame_meta
from .imap_analyzer import ImapAnalyzer
from .models import AnalysisContext, EmailSessionObs, EvidenceRef, StreamInfo, TlsSessionObs
from .pop3_analyzer import Pop3Analyzer
from .risk_engine import score_findings
from .sanitize import sanitize_layers
from .smtp_analyzer import SmtpAnalyzer
from .tcp_reassembly import FRAME_FIELDS, PAYLOAD_FIELDS, FrameTable, build_frame_table, identify_streams
from .tls_analyzer import analyze_tls

log = get_logger("engine")

STAGES = [
    ("file_validation", "File validation"),
    ("pcap_metadata", "PCAP metadata extraction"),
    ("packet_decoding", "Packet decoding"),
    ("protocol_identification", "Protocol identification"),
    ("stream_reconstruction", "TCP stream reconstruction"),
    ("session_identification", "Email-session identification"),
    ("starttls_analysis", "STARTTLS/STLS analysis"),
    ("tls_parsing", "TLS handshake parsing"),
    ("certificate_extraction", "Certificate metadata extraction"),
    ("rule_evaluation", "Deterministic security rule evaluation"),
    ("risk_prioritisation", "Risk prioritisation"),
    ("evidence_collection", "Evidence collection"),
    ("report_generation", "Report generation"),
]
STAGE_PCT = {k: round(100 * (i + 1) / len(STAGES)) for i, (k, _) in enumerate(STAGES)}

ProgressCb = Callable[[str, str, dict | None], None]  # (stage_key, message, counters)


@dataclass
class EngineResult:
    meta: CaptureMeta
    table: FrameTable
    streams: list[StreamInfo]
    sessions: list[EmailSessionObs]
    tls_sessions: list[TlsSessionObs]
    drafts: list[FindingDraft]
    risks: list[dict]
    evidence_index: dict[str, EvidenceRef]
    frame_trees: dict[int, dict]
    raw_hex: dict[int, str]
    limitations: list[str]
    errors: list[str]
    tool: dict
    decode_as: list[tuple[int, str]]
    counters: dict
    duration_s: float = 0.0


def _analyzer(proto: str) -> EmailAnalyzer:
    return {"smtp": SmtpAnalyzer, "imap": ImapAnalyzer, "pop3": Pop3Analyzer}[proto]()


def _carve_tls_after(path: Path, st: StreamInfo, table: FrameTable, after_frame: int, analysis_id: str | None):
    """TShark does not switch IMAP to TLS after STARTTLS. Re-dissect the post-STARTTLS bytes as TLS.

    Returns a list of (FrameMeta, layers) with frame numbers/stream ids mapped back to the original capture.
    """
    frames = sorted(n for n in table.stream_frames.get(st.stream_id, []) if n > after_frame)
    if not frames:
        return []
    with tempfile.TemporaryDirectory(prefix="sms_carve_") as td:
        derived = Path(td) / "derived.pcap"
        tsr.export_frames(path, frames, derived, analysis_id)
        layers_list = tsr.run_json(derived, display_filter="tls", layers="frame ip ipv6 tcp tls", decode_as=[(st.server_port, "tls")], analysis_id=analysis_id)
    out = []
    for layers in layers_list:
        m = frame_meta(layers)
        if 1 <= m.number <= len(frames):
            orig = frames[m.number - 1]
            m.number = orig
            m.stream = st.stream_id
            layers["frame"]["frame.number"] = str(orig)
            out.append((m, layers))
    return sorted(out, key=lambda x: x[0].number)


def run_engine(
    path: Path,
    capture_name: str,
    *,
    analysis_id: str | None = None,
    enabled_rules: set[str] | None = None,
    progress: ProgressCb | None = None,
    cert_reference: str = "capture",
    options: dict | None = None,
) -> EngineResult:
    opt = {"detect_smtp": True, "detect_imap": True, "detect_pop3": True, "inspect_tls": True, "inspect_certificates": True, "apply_rules": True, **(options or {})}
    t_start = time.time()
    cb = progress or (lambda *a, **k: None)
    limitations: list[str] = []
    errors: list[str] = []
    counters: dict = {"packets": 0, "streams": 0, "email_sessions": 0, "tls_handshakes": 0, "certificates": 0, "findings": 0}

    # 1 ----------------------------------------------------------------- validation
    cb("file_validation", "Validating capture file by content", counters)
    meta = validate_capture(path)
    tool = tsr.tool_info()
    if not tool["available"]:
        raise tsr.TsharkNotFound(tool.get("error", "TShark unavailable"))

    # 2 ----------------------------------------------------------------- metadata
    cb("pcap_metadata", f"{meta.format.upper()} capture, link type {meta.linktype_name}, {meta.packet_count} packets", counters)
    if meta.truncated_tail:
        limitations.append("The capture file ends with a truncated record; the final packet was cut short.")

    # 3 ----------------------------------------------------------------- packet decoding
    cb("packet_decoding", "Decoding frames with TShark", counters)
    rows = list(tsr.run_fields(path, FRAME_FIELDS, analysis_id=analysis_id))
    table = build_frame_table(rows)
    if table.total_frames > settings.max_packets:
        raise ValueError(f"Capture has {table.total_frames} packets, above the configured limit ({settings.max_packets}).")
    counters.update(packets=table.total_frames, streams=len(table.streams))
    cb("packet_decoding", f"{table.total_frames} frames decoded ({table.tcp_frames} TCP)", counters)
    if table.tcp_frames == 0:
        limitations.append("No TCP traffic was found in the capture; email protocols are carried over TCP.")

    # 4 ----------------------------------------------------------------- protocol identification
    cb("protocol_identification", "Matching banners/commands and ports to email protocols", counters)
    payload_rows = list(tsr.run_fields(path, PAYLOAD_FIELDS, display_filter="tcp.len>0 && tcp.seq==1", analysis_id=analysis_id))
    decode_as = identify_streams(table, payload_rows)
    skipped = {p for p, key in (("smtp", "detect_smtp"), ("imap", "detect_imap"), ("pop3", "detect_pop3")) if not opt[key]}
    email_streams = {sid: st for sid, st in table.streams.items() if st.protocol and st.protocol not in skipped}
    if skipped:
        limitations.append("Protocol detection disabled by analysis options for: " + ", ".join(sorted(p.upper() for p in skipped)) + ".")
    cb("protocol_identification", f"{len(email_streams)} email stream(s) identified" + (f"; decode-as on non-default ports {[p for p, _ in decode_as]}" if decode_as else ""), counters)

    # 5 ----------------------------------------------------------------- stream reconstruction / dissection
    cb("stream_reconstruction", "Two-pass TCP reassembly and protocol dissection (TShark)", counters)
    by_stream: dict[int, list[tuple[FrameMeta, dict]]] = {}
    other_tls: set[int] = set()
    if email_streams:
        for layers in tsr.run_json(path, display_filter="smtp || imap || pop || tls", decode_as=decode_as, analysis_id=analysis_id):
            m = frame_meta(layers)
            if m.stream is None:
                continue
            if m.stream in email_streams:
                by_stream.setdefault(m.stream, []).append((m, layers))
            elif "tls" in layers:
                other_tls.add(m.stream)
        for fl in by_stream.values():
            fl.sort(key=lambda x: x[0].number)
    elif any("tls" in "" for _ in []):
        pass
    if other_tls:
        limitations.append(f"{len(other_tls)} TLS stream(s) on non-email ports were detected and intentionally not analysed.")
    retrans = sum(s.retransmissions for s in email_streams.values())
    ooo = sum(s.out_of_order for s in email_streams.values())
    lost = sum(s.lost_segments for s in email_streams.values())
    cb("stream_reconstruction", f"{len(email_streams)} stream(s) reassembled; {retrans} retransmission(s), {ooo} out-of-order, {lost} missing segment(s) flagged by TShark", counters)
    if lost:
        limitations.append(f"TShark flagged {lost} missing TCP segment(s) in email streams; reassembled content may be incomplete.")
    nosyn = [s.stream_id for s in email_streams.values() if not s.syn]
    if nosyn:
        limitations.append(f"Stream(s) {nosyn} start mid-connection (no SYN captured); client/server roles were inferred from payload/ports.")

    # 6 ----------------------------------------------------------------- sessions
    cb("session_identification", "Extracting SMTP/IMAP/POP3 protocol events (credentials and bodies are never stored)", counters)
    sessions: list[EmailSessionObs] = []
    for sid, st in sorted(email_streams.items()):
        s = EmailSessionObs(sid, st.protocol, st.client_ip, st.client_port, st.server_ip, st.server_port, st.first_ts, st.last_ts,
                            detected_by=st.detected_by or "port", implicit_tls=st.implicit_tls)
        s.stream_completeness = st.completeness
        if st.implicit_tls:
            s.notes.append("Connection starts directly with a TLS record (implicit TLS); no cleartext protocol events exist.")
        else:
            _analyzer(st.protocol).process(s, by_stream.get(sid, []))
            if not s.events:
                s.notes.append("No decodable protocol events were found in this stream.")
        sessions.append(s)
    counters["email_sessions"] = len(sessions)
    cb("session_identification", f"{len(sessions)} email session(s)", counters)

    # 7 ----------------------------------------------------------------- STARTTLS / carving
    cb("starttls_analysis", "Analysing STARTTLS/STLS negotiation and the TLS transition", counters)
    carved: dict[int, list[tuple[FrameMeta, dict]]] = {}
    for s in sessions:
        st = email_streams[s.stream_id]
        has_tls = any("tls" in l for _, l in by_stream.get(s.stream_id, []))
        if s.starttls_accepted and not has_tls and s.starttls_response:
            frames = _carve_tls_after(path, st, table, s.starttls_response.frame, analysis_id)
            if frames:
                carved[s.stream_id] = frames
                s.notes.append("TShark's dissector does not follow this protocol's STARTTLS into TLS; post-STARTTLS bytes were re-dissected as TLS from a derived capture.")
    cb("starttls_analysis", f"{sum(1 for s in sessions if s.starttls_command)} session(s) with a STARTTLS/STLS command", counters)

    # 8/9 --------------------------------------------------------------- TLS + certificates
    cb("tls_parsing", "Parsing ClientHello / ServerHello / extensions", counters)
    tls_sessions: list[TlsSessionObs] = []
    for sid, st in sorted(email_streams.items()):
        frames = carved.get(sid) or by_stream.get(sid, [])
        sess = session_for(AnalysisContext(capture_name, None, sessions, [], []), sid)
        t = analyze_tls(st, frames, sess) if opt["inspect_tls"] else None
        if t:
            tls_sessions.append(t)
            if sess:
                sess.tls_after_starttls = bool(sess.starttls_accepted and t.client_hello_frame)
    counters["tls_handshakes"] = sum(1 for t in tls_sessions if t.server_hello_frame)
    cb("tls_parsing", f"{len(tls_sessions)} TLS session(s), {counters['tls_handshakes']} with a ServerHello", counters)
    if not opt["inspect_tls"]:
        limitations.append("TLS inspection was disabled by analysis options.")
    if not opt["inspect_certificates"]:
        for t in tls_sessions:
            t.certificates = []
        limitations.append("Certificate inspection was disabled by analysis options; certificate rules did not run on real data.")
    cb("certificate_extraction", "Extracting certificate metadata where visible (no trust validation)", counters)
    counters["certificates"] = sum(len(t.certificates) for t in tls_sessions)
    cb("certificate_extraction", f"{counters['certificates']} certificate(s) extracted", counters)
    if any(t.tls13 for t in tls_sessions):
        limitations.append("TLS 1.3 session(s): the server Certificate is encrypted after the ServerHello, so certificate details are unavailable without authorised key material.")
    if any(t.ech_seen for t in tls_sessions):
        limitations.append("Encrypted Client Hello was observed; inner ClientHello details are hidden.")

    # frame trees (sanitised) for later evidence display ----------------------
    frame_trees: dict[int, dict] = {}
    event_by_frame = {(e.frame): e.summary for s in sessions for e in s.events}
    for sid in list(by_stream) + list(carved):
        for m, layers in (carved.get(sid) or by_stream.get(sid, []))[:600]:
            frame_trees[m.number] = sanitize_layers(layers, event_by_frame.get(m.number))
    for sid, fl in by_stream.items():  # keep original text-frame trees even when TLS was carved
        for m, layers in fl[:600]:
            frame_trees.setdefault(m.number, sanitize_layers(layers, event_by_frame.get(m.number)))

    # 10 ---------------------------------------------------------------- rules
    cb("rule_evaluation", "Evaluating deterministic rules", counters)
    ctx = AnalysisContext(capture_name, table.last_ts, sessions, tls_sessions, list(table.streams.values()), cert_reference=cert_reference)
    if cert_reference == "analysis":
        ctx.cert_reference_ts = time.time()
        for t in tls_sessions:
            for c in t.certificates:
                c.ts = None
    drafts: list[FindingDraft] = []
    if not opt["apply_rules"]:
        limitations.append("Rule evaluation was disabled by analysis options; only raw observations are reported.")
    for rule in (all_rules() if opt["apply_rules"] else []):
        if enabled_rules is not None and rule.meta.rule_id not in enabled_rules:
            continue
        try:
            drafts.extend(rule.evaluate(ctx))
        except Exception as exc:  # never swallow silently: surface in the result
            log.exception("rule %s failed", rule.meta.rule_id)
            errors.append(f"Rule {rule.meta.rule_id} failed: {exc}")
    counters["findings"] = len(drafts)
    cb("rule_evaluation", f"{len(drafts)} finding(s) produced", counters)

    # 11 ---------------------------------------------------------------- risk
    cb("risk_prioritisation", "Scoring findings (SMRS-1, deterministic)", counters)
    risks = score_findings(drafts)
    cb("risk_prioritisation", "Risk scores computed", counters)

    # 12 ---------------------------------------------------------------- evidence
    cb("evidence_collection", "Collecting packet-level evidence and raw handshake bytes", counters)
    raw_hex = _collect_raw_hex(path, drafts, analysis_id, errors)
    cb("evidence_collection", f"{sum(len(d.evidence) for d in drafts)} evidence record(s)", counters)

    if not email_streams:
        limitations.append("No SMTP, IMAP or POP3 traffic was identified in this capture.")
    limitations.append("Passive analysis of observable data only: no decryption, no traffic injection, no certificate trust (chain/revocation) validation.")

    return EngineResult(meta, table, list(table.streams.values()), sessions, tls_sessions, drafts, risks, ctx.evidence_index, frame_trees,
                        raw_hex, limitations, errors, tool, decode_as, counters, round(time.time() - t_start, 3))


def _collect_raw_hex(path: Path, drafts: list[FindingDraft], analysis_id: str | None, errors: list[str]) -> dict[int, str]:
    """Raw bytes only for TLS *handshake* evidence frames (public handshake data, no payload secrets)."""
    frames = sorted({e.frame for d in drafts for e in d.evidence if e.protocol == "TLS" and e.frame})[:40]
    if not frames:
        return {}
    try:
        expr = "frame.number in {" + ", ".join(str(f) for f in frames) + "}"
        out: dict[int, str] = {}
        for layers in tsr.run_json(path, display_filter=expr, layers="frame", raw_hex=True, analysis_id=analysis_id):
            raw = layers.get("frame_raw")
            n = int(layers["frame"]["frame.number"])
            if raw:
                out[n] = raw[0] if isinstance(raw, list) else raw
        return out
    except tsr.TsharkError as exc:
        errors.append(f"Raw byte extraction failed (hex view unavailable): {exc}")
        return {}
