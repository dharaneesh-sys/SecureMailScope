from app.services.models import AnalysisContext, CertObs, EmailSessionObs, ProtoEvent, TlsSessionObs

CAPTURE_TS = 1_767_225_600.0  # 2026-01-01


def tls(**kw) -> TlsSessionObs:
    base = dict(stream_id=0, client_ip="192.0.2.10", client_port=40000, server_ip="198.51.100.25", server_port=25, carrier_protocol="smtp", via_starttls=True,
                client_hello_frame=14, client_hello_ts=CAPTURE_TS, client_legacy_version=0x0303, offered_ciphers=[0xC030], sni="mail.example.test",
                server_hello_frame=16, server_hello_ts=CAPTURE_TS, selected_version=0x0303, selected_version_source="server_version", selected_cipher=0xC030,
                server_hello_done=True, certificate_frame=16)
    base.update(kw)
    return TlsSessionObs(**base)


def cert(**kw) -> CertObs:
    base = dict(stream_id=0, position=0, frame=16, subject="CN=mail.example.test", issuer="CN=Test CA", serial="01", not_before="2025-12-01T00:00:00+00:00",
                not_after="2027-06-01T00:00:00+00:00", sig_algorithm="sha256WithRSAEncryption", sig_hash="sha256", key_algorithm="RSA", key_size=2048,
                san=["mail.example.test"], sha256="ab" * 32, self_signed=False, is_ca=False, der_len=700, ts=CAPTURE_TS)
    base.update(kw)
    return CertObs(**base)


def session(protocol="smtp", **kw) -> EmailSessionObs:
    base = dict(stream_id=0, protocol=protocol, client_ip="192.0.2.10", client_port=40000, server_ip="198.51.100.25", server_port=25, first_ts=CAPTURE_TS, last_ts=CAPTURE_TS)
    base.update(kw)
    return EmailSessionObs(**base)


def ev(frame, summary="x", direction="client->server") -> ProtoEvent:
    return ProtoEvent(frame, 0, CAPTURE_TS, direction, "command", "X", summary)


def ctx(sessions=(), tls_sessions=()) -> AnalysisContext:
    return AnalysisContext("t.pcap", CAPTURE_TS, list(sessions), list(tls_sessions), [], cert_reference_ts=CAPTURE_TS)


def fire(rule_id, c):
    from app.rules.registry import get_rule

    return get_rule(rule_id).evaluate(c)
