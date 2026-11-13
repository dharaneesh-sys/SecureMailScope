"""TLS protocol-version rules and evidence-sufficiency rules."""

from __future__ import annotations

from app.services.cipher_catalog import DEPRECATED_VERSIONS, classify, version_name
from app.services.models import AnalysisContext

from .base import Rule, RuleMeta, ev_event, ev_tls
from .registry import register


def _hello_fields(t) -> dict:
    return {"tls.handshake.type": "ClientHello", "client_legacy_version": version_name(t.client_legacy_version),
            "supported_versions": [version_name(v) for v in t.client_supported_versions] or None, "sni": t.sni}


def _sh_fields(t) -> dict:
    return {"tls.handshake.type": "ServerHello", "selected_version": version_name(t.selected_version),
            "version_source": t.selected_version_source, "selected_cipher": classify(t.selected_cipher).name if t.selected_cipher is not None else None}


@register
class DeprecatedTlsSelected(Rule):
    meta = RuleMeta("SMS-TLS-001", "Deprecated TLS/SSL version negotiated", "Deprecated TLS", "high",
        "The server selected SSL 3.0, TLS 1.0 or TLS 1.1, all formally deprecated.",
        "ServerHello selected version (supported_versions extension, else server_version) is in {SSLv2, SSLv3, TLSv1.0, TLSv1.1}.",
        "ServerHello frame.",
        "Disable SSLv3/TLS 1.0/TLS 1.1 on the mail server; require TLS 1.2 or TLS 1.3.",
        references=("RFC 8996", "NIST SP 800-52r2"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            if t.server_hello_frame and t.selected_version in DEPRECATED_VERSIONS:
                v = version_name(t.selected_version)
                out.append(self.draft(
                    title=f"Deprecated protocol version {v} negotiated", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    severity="critical" if t.selected_version <= 0x0300 else "high",
                    description=f"The server selected {v}, which is deprecated.",
                    technical=f"ServerHello (frame {t.server_hello_frame}) selected {v} (source: {t.selected_version_source}).",
                    impact="Deprecated versions lack modern protections and are exposed to known downgrade and padding/CBC attacks (e.g. POODLE, BEAST).",
                    observation_type="weakness_observed", completeness=t.completeness,
                    evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, f"ServerHello selected {v}", _sh_fields(t), "server->client", t.completeness)]))
        return out


@register
class DeprecatedTlsOffered(Rule):
    meta = RuleMeta("SMS-TLS-002", "Client offers deprecated TLS versions", "Deprecated TLS", "low",
        "The ClientHello advertised deprecated protocol versions via supported_versions although a modern version was selected.",
        "supported_versions in the ClientHello contains a deprecated version AND the selected version is not deprecated (or unknown).",
        "ClientHello frame.",
        "Remove TLS 1.0/1.1 from the client's allowed protocol versions.", references=("RFC 8996",))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            if not t.client_hello_frame or t.selected_version in DEPRECATED_VERSIONS:
                continue
            dep = [v for v in t.client_supported_versions if v in DEPRECATED_VERSIONS]
            if not dep:
                continue
            out.append(self.draft(
                title="Client offered deprecated TLS versions", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                description="The client was willing to negotiate deprecated protocol versions.",
                technical="supported_versions offered: " + ", ".join(version_name(v) for v in t.client_supported_versions),
                impact="Offering deprecated versions leaves the client exposed to downgrade attacks if the peer or an on-path attacker prefers them.",
                observation_type="weak_option_offered", completeness=t.completeness,
                evidence=[ev_tls(t, t.client_hello_frame, t.client_hello_ts, "ClientHello supported_versions", _hello_fields(t), "client->server", t.completeness)]))
        return out


@register
class HandshakeIncomplete(Rule):
    meta = RuleMeta("SMS-TLS-010", "TLS handshake incomplete in capture", "Incomplete TLS evidence", "info",
        "Both hellos were captured but the remainder of the handshake (certificate / hello-done) was not, so certificate analysis is limited.",
        "ClientHello AND ServerHello observed AND (not TLS 1.3) AND neither Certificate nor ServerHelloDone observed.",
        "ClientHello and ServerHello frames.", "Re-capture the full connection from the TCP SYN if certificate details are required.")

    def evaluate(self, ctx: AnalysisContext):
        return [self.draft(
            title="TLS handshake only partially captured", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
            description="Hellos were captured but the handshake is incomplete; this is a limitation of the capture, not a confirmed weakness.",
            technical=f"ClientHello frame {t.client_hello_frame}, ServerHello frame {t.server_hello_frame}; no Certificate/ServerHelloDone observed.",
            impact="Version and cipher findings are valid; certificate checks could not be performed.",
            observation_type="insufficient_evidence", completeness="partial",
            evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello (last handshake message observed)", _sh_fields(t), "server->client", "partial")])
            for t in ctx.tls_sessions if t.completeness == "partial"]


@register
class ClientHelloUnavailable(Rule):
    meta = RuleMeta("SMS-TLS-011", "ClientHello not observed", "Incomplete TLS evidence", "info",
        "A ServerHello was captured without its ClientHello, so offered cipher suites and extensions are unknown.",
        "ServerHello observed AND no ClientHello observed in the stream.", "ServerHello frame.", "Capture from the start of the TLS exchange.")

    def evaluate(self, ctx: AnalysisContext):
        return [self.draft(
            title="ClientHello unavailable", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
            description="The client's offered parameters cannot be assessed because the ClientHello is missing from the capture.",
            technical=f"ServerHello at frame {t.server_hello_frame}; no ClientHello in stream {t.stream_id}.",
            impact="Offered-cipher and client-capability rules were not evaluated for this session.",
            observation_type="insufficient_evidence", completeness="incomplete",
            evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello without preceding ClientHello", _sh_fields(t), "server->client", "incomplete")])
            for t in ctx.tls_sessions if t.server_hello_frame and not t.client_hello_frame]


@register
class ServerHelloUnavailable(Rule):
    meta = RuleMeta("SMS-TLS-012", "ServerHello not observed", "Incomplete TLS evidence", "info",
        "A ClientHello was captured but no ServerHello followed, so the negotiated version and cipher are unknown.",
        "ClientHello observed AND no ServerHello observed in the stream.", "ClientHello frame.", "Capture the complete connection, including server responses.")

    def evaluate(self, ctx: AnalysisContext):
        return [self.draft(
            title="ServerHello unavailable", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
            description="The negotiated TLS version and cipher suite cannot be determined; no weakness is asserted.",
            technical=f"ClientHello at frame {t.client_hello_frame}; no ServerHello observed (capture ends or direction missing).",
            impact="Negotiated-parameter rules (version, selected cipher, certificate) were not evaluated for this session.",
            observation_type="insufficient_evidence", completeness="incomplete",
            evidence=[ev_tls(t, t.client_hello_frame, t.client_hello_ts, "ClientHello (last handshake message observed)", _hello_fields(t), "client->server", "incomplete")])
            for t in ctx.tls_sessions if t.client_hello_frame and not t.server_hello_frame]


@register
class InsufficientTlsEvidence(Rule):
    meta = RuleMeta("SMS-TLS-013", "Insufficient evidence to assess TLS posture", "Incomplete TLS evidence", "info",
        "TLS posture cannot be assessed because the negotiated parameters are not in the capture.",
        "(TLS stream seen with no ServerHello) OR (STARTTLS/STLS accepted but no TLS records observed after it).",
        "STARTTLS response frame, or the last TLS frame observed.", "Re-capture the full session; do not treat this as either secure or insecure.")

    def evaluate(self, ctx: AnalysisContext):
        out = []
        tls_ids = {t.stream_id for t in ctx.tls_sessions}
        for s in ctx.sessions:
            if s.starttls_accepted and s.stream_id not in tls_ids:
                out.append(self.draft(
                    title=f"{s.protocol.upper()} TLS upgrade accepted but no TLS data captured", stream=s.stream_id, protocol=s.protocol.upper(),
                    description="The server accepted the TLS upgrade, but no TLS handshake appears afterwards. The TLS posture is unknown, not confirmed insecure.",
                    technical=f"Accepted at frame {s.starttls_response.frame}; no TLS records seen later in stream {s.stream_id}.",
                    impact="Capture truncation, packet loss or an unsupported/undecodable transport could explain this. No cryptographic conclusion can be drawn.",
                    observation_type="insufficient_evidence", completeness="incomplete",
                    evidence=[ev_event(s, s.starttls_response, "Server accepted TLS upgrade; nothing decodable followed")]))
        for t in ctx.tls_sessions:
            if not t.server_hello_frame:
                last = t.frames[-1] if t.frames else None
                out.append(self.draft(
                    title="TLS posture cannot be assessed (no ServerHello)", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description="Without a ServerHello the negotiated version, cipher and certificate are unknown.",
                    technical=f"TLS records observed in frames {t.frames[:6]}; no ServerHello found.",
                    impact="Only the client's offer is visible; the final configuration is undetermined.",
                    observation_type="insufficient_evidence", completeness="incomplete",
                    evidence=[ev_tls(t, last, t.first_ts, "Last TLS frame observed", {"frames": t.frames[:10]}, "client->server", "incomplete")]))
        return out


@register
class SecureConfiguration(Rule):
    meta = RuleMeta("SMS-TLS-014", "Modern TLS configuration observed", "Secure configuration", "info",
        "TLS 1.3, or TLS 1.2 with an AEAD forward-secret cipher suite, was negotiated.",
        "Selected version is TLS 1.3, or TLS 1.2 with a known AEAD cipher using ECDHE/DHE key exchange.",
        "ServerHello frame.", "No action required.", references=("NIST SP 800-52r2", "RFC 8446"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            if not t.server_hello_frame or t.selected_cipher is None:
                continue
            ci = classify(t.selected_cipher)
            ok = t.selected_version == 0x0304 or (t.selected_version == 0x0303 and ci.known and ci.aead and ci.forward_secret and not ci.is_weak)
            if ok:
                out.append(self.draft(
                    title=f"{version_name(t.selected_version)} with {ci.name} negotiated", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description="A modern protocol version and cipher suite were negotiated.",
                    technical=f"ServerHello frame {t.server_hello_frame}: {version_name(t.selected_version)}, {ci.name}.",
                    impact="Positive observation. Certificate and configuration details are assessed separately.",
                    observation_type="secure_configuration", completeness=t.completeness,
                    evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello with modern parameters", _sh_fields(t), "server->client", t.completeness)]))
        return out
