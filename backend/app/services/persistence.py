"""Persist an :class:`EngineResult` into SQLite."""

from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from app.models.tables import (Analysis, CertificateRow, EmailSessionRow, EvidenceRow, Finding, PacketMeta, TcpStreamRow,
                               TlsCipherObservation, TlsSessionRow)

from .certificate_analyzer import parse_iso
from .cipher_catalog import SIGNALLING, classify, version_name
from .engine import EngineResult
from .models import EmailSessionObs, TlsSessionObs
from .rules_sync_ref import rule_versions_map

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ep(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _session_states(s: EmailSessionObs, tls: TlsSessionObs | None) -> dict:
    cmd = {"smtp": "STARTTLS", "imap": "STARTTLS", "pop3": "STLS"}[s.protocol]
    st: dict = {}
    st["greeting"] = "observed" if s.banner else ("not_observed" if not s.implicit_tls else "undecodable")
    st["capabilities"] = "observed" if s.capabilities else ("undecodable" if s.implicit_tls else "not_observed")
    st[cmd.lower() + "_command"] = "observed" if s.starttls_command else ("undecodable" if s.implicit_tls else "not_observed")
    if s.starttls_command:
        st[cmd.lower() + "_response"] = "observed" if s.starttls_response else "incomplete"
    if s.starttls_accepted:
        st["tls_transition"] = "observed" if tls and tls.client_hello_frame else "incomplete"
    elif s.starttls_command and s.starttls_accepted is False:
        st["tls_transition"] = "not_observed"
    elif s.implicit_tls:
        st["tls_transition"] = "observed"
    st["content_after_tls"] = "undecodable" if (tls or s.implicit_tls) else "not_observed"
    return st


def persist_result(db: Session, analysis: Analysis, r: EngineResult, ruleset_sig: str) -> None:
    aid = analysis.id
    ver_map = rule_versions_map()
    sess_by_stream = {s.stream_id: s for s in r.sessions}
    tls_by_stream = {t.stream_id: t for t in r.tls_sessions}

    for st in list(r.streams)[:5000]:
        db.add(TcpStreamRow(analysis_id=aid, stream_id=st.stream_id, client=_ep(st.client_ip, st.client_port), server=_ep(st.server_ip, st.server_port),
                            protocol=st.protocol, detected_by=st.detected_by, frames=st.frames, first_ts=st.first_ts, last_ts=st.last_ts, completeness=st.completeness,
                            quality={"syn": st.syn, "fin": st.fin, "rst": st.rst, "retransmissions": st.retransmissions, "out_of_order": st.out_of_order, "lost_segments": st.lost_segments}))

    for s in r.sessions:
        t = tls_by_stream.get(s.stream_id)
        db.add(EmailSessionRow(
            analysis_id=aid, stream_id=s.stream_id, protocol=s.protocol, client=_ep(s.client_ip, s.client_port), server=_ep(s.server_ip, s.server_port),
            first_ts=s.first_ts, last_ts=s.last_ts, banner=s.banner, implicit_tls=s.implicit_tls, detected_by=s.detected_by, capabilities=s.capabilities,
            starttls={"offered": s.starttls_offered, "command_frame": s.starttls_command.frame if s.starttls_command else None,
                      "response_frame": s.starttls_response.frame if s.starttls_response else None, "accepted": s.starttls_accepted,
                      "tls_followed": bool(t and t.client_hello_frame)},
            events=[{"frame": e.frame, "ts": e.ts, "direction": e.direction, "kind": e.kind, "verb": e.verb, "summary": e.summary, "state": e.state} for e in s.events],
            states=_session_states(s, t), notes=s.notes, completeness=s.stream_completeness))

    for t in r.tls_sessions:
        ch = None
        if t.client_hello_frame:
            ch = {"frame": t.client_hello_frame, "ts": t.client_hello_ts, "legacy_version": version_name(t.client_legacy_version),
                  "supported_versions": [version_name(v) for v in t.client_supported_versions], "sni": t.sni, "alpn": t.alpn,
                  "supported_groups": t.supported_groups, "signature_algorithms": t.signature_algorithms, "extensions": t.extensions_offered,
                  "cipher_suites": [{"id": f"0x{c:04X}", "name": classify(c).name, "weak_class": classify(c).weak_class, "known": classify(c).known} for c in t.offered_ciphers]}
        sh = None
        if t.server_hello_frame:
            ci = classify(t.selected_cipher) if t.selected_cipher is not None else None
            sh = {"frame": t.server_hello_frame, "ts": t.server_hello_ts, "legacy_version": version_name(t.server_legacy_version),
                  "selected_version": version_name(t.selected_version), "version_source": t.selected_version_source,
                  "cipher_suite": ({"id": f"0x{ci.id:04X}", "name": ci.name, "weak_class": ci.weak_class, "forward_secret": ci.forward_secret, "aead": ci.aead} if ci else None),
                  "extensions": t.server_extensions}
        row = TlsSessionRow(analysis_id=aid, stream_id=t.stream_id, carrier_protocol=t.carrier_protocol, via_starttls=t.via_starttls,
                            client=_ep(t.client_ip, t.client_port), server=_ep(t.server_ip, t.server_port), record_versions=t.record_versions,
                            client_hello=ch, server_hello=sh, selected_version=version_name(t.selected_version),
                            selected_cipher=classify(t.selected_cipher).name if t.selected_cipher is not None else None,
                            completeness=t.completeness, notes=t.notes,
                            flags={"tls13": t.tls13, "ech": t.ech_seen, "certificate_visible": bool(t.certificates), "server_hello_done": t.server_hello_done,
                                   "change_cipher_spec": t.change_cipher_spec_seen, "encrypted_after_hello": t.encrypted_after_hello, "alerts": t.alerts,
                                   "frames": t.frames[:40]})
        db.add(row)
        db.flush()
        for c in t.offered_ciphers:
            if c in SIGNALLING:
                continue
            ci = classify(c)
            db.add(TlsCipherObservation(tls_session_id=row.id, analysis_id=aid, suite_id=c, name=ci.name, role="offered", weak_class=ci.weak_class, forward_secret=ci.forward_secret))
        if t.selected_cipher is not None:
            ci = classify(t.selected_cipher)
            db.add(TlsCipherObservation(tls_session_id=row.id, analysis_id=aid, suite_id=ci.id, name=ci.name, role="selected", weak_class=ci.weak_class, forward_secret=ci.forward_secret))
        for c in t.certificates:
            ref = dt.datetime.fromtimestamp(c.ts or r.table.last_ts or 0, dt.timezone.utc)
            nb, na = parse_iso(c.not_before), parse_iso(c.not_after)
            weak_key = c.key_size is not None and ((c.key_algorithm in ("RSA", "DSA") and c.key_size < 2048) or (c.key_algorithm.startswith("EC") and c.key_size < 224))
            checks = [
                {"check": "Validity at capture time", "result": "fail" if (na < ref or nb > ref) else "pass", "detail": f"valid {c.not_before[:10]} to {c.not_after[:10]}; reference {ref.date()}"},
                {"check": "Signature algorithm", "result": "fail" if c.sig_hash in ("md5", "sha1") else ("pass" if c.sig_hash else "unknown"), "detail": c.sig_algorithm},
                {"check": "Public key strength", "result": "fail" if weak_key else ("pass" if c.key_size else "unknown"), "detail": f"{c.key_algorithm} {c.key_size or '?'} bits"},
                {"check": "Self-signed", "result": "info" if c.self_signed else "pass", "detail": "subject equals issuer" if c.self_signed else "issuer differs from subject"},
                {"check": "Trust chain validation", "result": "not_performed", "detail": "Metadata extraction only: no trust store or revocation check was used."},
            ]
            db.add(CertificateRow(analysis_id=aid, stream_id=t.stream_id, position=c.position, frame=c.frame, subject=c.subject[:400], issuer=c.issuer[:400],
                                  serial=c.serial, not_before=c.not_before, not_after=c.not_after, sig_algorithm=c.sig_algorithm, key_algorithm=c.key_algorithm,
                                  key_size=c.key_size, san=c.san, sha256=c.sha256, self_signed=c.self_signed, checks=checks))

    # findings (ordered by score) + evidence + packet metadata
    order = sorted(range(len(r.drafts)), key=lambda i: (-r.risks[i]["score"], SEV_ORDER[r.drafts[i].severity]))
    ev_n = 0
    frames_needed: dict[int, tuple] = {}
    for n, i in enumerate(order, 1):
        d, risk = r.drafts[i], r.risks[i]
        f = Finding(analysis_id=aid, ref=f"F-{n:04d}", rule_id=d.rule_id, title=d.title[:240], severity=d.severity, category=d.category, protocol=d.protocol,
                    stream_id=d.stream_id, description=d.description, technical=d.technical, impact=d.impact, remediation=d.remediation,
                    observation_type=d.observation_type, completeness=d.completeness, risk_score=risk["score"], risk=risk, rule_version=ver_map.get(d.rule_id, 1))
        db.add(f)
        db.flush()
        for e in d.evidence:
            ev_n += 1
            db.add(EvidenceRow(ref=f"E-{ev_n:04d}", analysis_id=aid, finding_id=f.id, frame=e.frame, stream_id=e.stream, direction=e.direction, timestamp=e.timestamp,
                               protocol=e.protocol, description=e.description, fields={k: v for k, v in e.fields.items() if v is not None}, parser=e.parser, completeness=e.completeness))
            if e.frame:
                frames_needed.setdefault(e.frame, (e.stream, e.timestamp, e.direction, e.protocol))
    for fr, (stream, ts, direction, proto) in sorted(frames_needed.items()):
        db.add(PacketMeta(analysis_id=aid, frame_number=fr, stream_id=stream, timestamp=ts, direction=direction, protocol=proto,
                          tree=r.frame_trees.get(fr), raw_hex=r.raw_hex.get(fr)))
    analysis.counters = {**r.counters, "findings": len(r.drafts), "evidence": ev_n}
    analysis.limitations = r.limitations
    analysis.engine_errors = r.errors
    analysis.tool_info = {**r.tool, "decode_as": [f"tcp.port=={p},{pr}" for p, pr in r.decode_as], "duration_s": r.duration_s}
    analysis.ruleset_version = ruleset_sig
    db.commit()
