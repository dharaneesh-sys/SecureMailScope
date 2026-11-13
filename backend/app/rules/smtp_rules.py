"""STARTTLS / STLS and plaintext-authentication rules (SMTP, IMAP, POP3)."""

from __future__ import annotations

from app.services.models import AnalysisContext

from .base import Rule, RuleMeta, ev_event, ev_tls, tls_for
from .registry import register

CMD = {"smtp": "STARTTLS", "imap": "STARTTLS", "pop3": "STLS"}


@register
class StarttlsObserved(Rule):
    meta = RuleMeta("SMS-STL-001", "STARTTLS/STLS negotiation observed", "STARTTLS/STLS observations", "info",
        "The client requested an upgrade to TLS, the server accepted it, and a TLS ClientHello followed on the same connection.",
        "starttls_command observed AND server accepted (SMTP 220 / IMAP OK / POP3 +OK) AND a TLS ClientHello observed afterwards in the same stream.",
        "Command frame, accepting response frame, TLS ClientHello frame.",
        "No action required. Prefer implicit TLS (ports 465/993/995) where possible to remove downgrade exposure.",
        references=("RFC 3207", "RFC 8314"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for s in ctx.sessions:
            t = tls_for(ctx, s.stream_id)
            if s.starttls_accepted and t and t.client_hello_frame:
                s.tls_after_starttls = True
                cmd = CMD[s.protocol]
                out.append(self.draft(
                    title=f"{s.protocol.upper()} {cmd} negotiation observed and followed by TLS",
                    stream=s.stream_id, protocol=s.protocol.upper(),
                    description=f"The {s.protocol.upper()} client issued {cmd}, the server accepted, and a TLS handshake started on the same connection.",
                    technical=f"{cmd} at frame {s.starttls_command.frame}, accepted at frame {s.starttls_response.frame}, ClientHello at frame {t.client_hello_frame}.",
                    impact="Positive observation: the session was upgraded to TLS. This does not by itself prove the resulting TLS configuration is strong; see the TLS findings.",
                    observation_type="protocol_feature", completeness="complete",
                    evidence=[ev_event(s, s.starttls_command, f"Client sent {cmd}"), ev_event(s, s.starttls_response, "Server accepted the upgrade"),
                              ev_tls(t, t.client_hello_frame, t.client_hello_ts, "TLS ClientHello following the upgrade", {"tls.handshake.type": "ClientHello"}, "client->server")]))
        return out


@register
class StarttlsRejected(Rule):
    meta = RuleMeta("SMS-STL-002", "STARTTLS/STLS rejected by server", "STARTTLS/STLS observations", "medium",
        "The client asked for TLS but the server refused the upgrade, so the session continued (or ended) without encryption negotiated.",
        "starttls_command observed AND server response is a failure (SMTP non-220 / IMAP NO,BAD / POP3 -ERR).",
        "Command frame and the refusing response frame.",
        "Fix the server's TLS configuration so STARTTLS succeeds, and configure clients to require TLS (no fallback to plaintext).",
        references=("RFC 3207 §4", "RFC 8314"))

    def evaluate(self, ctx: AnalysisContext):
        return [self.draft(
            title=f"{s.protocol.upper()} {CMD[s.protocol]} was rejected by the server", stream=s.stream_id, protocol=s.protocol.upper(),
            description=f"The server answered the {CMD[s.protocol]} request with a failure response ({s.starttls_response.summary}).",
            technical=f"Command frame {s.starttls_command.frame}; response frame {s.starttls_response.frame}: {s.starttls_response.summary}",
            impact="A client that tolerates this will continue in cleartext, exposing message metadata and possibly credentials to network observers.",
            observation_type="weakness_observed", completeness="complete",
            evidence=[ev_event(s, s.starttls_command, "Client requested TLS upgrade"), ev_event(s, s.starttls_response, "Server refused")])
            for s in ctx.sessions if s.starttls_command and s.starttls_response and s.starttls_accepted is False]


@register
class PlaintextAfterOffer(Rule):
    meta = RuleMeta("SMS-STL-003", "TLS offered but session continued in plaintext", "STARTTLS/STLS observations", "medium",
        "The server advertised STARTTLS/STLS, the client never requested it, and mail/mailbox commands were exchanged in cleartext.",
        "starttls_offered is true (capability list observed) AND no STARTTLS command AND no TLS observed in the stream AND cleartext transaction or authentication commands observed.",
        "Capability response frame and at least one cleartext command frame.",
        "Configure the client/MTA to require STARTTLS (e.g. Postfix smtp_tls_security_level=encrypt) or move to implicit TLS.",
        references=("RFC 8314", "RFC 3207"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for s in ctx.sessions:
            if s.implicit_tls or s.starttls_offered is not True or s.starttls_command or tls_for(ctx, s.stream_id):
                continue
            used = s.auth_events + s.plaintext_transaction
            if not used:
                continue
            cap = next((e for e in s.events if e.kind == "capability"), None)
            ev = [ev_event(s, cap, "Server advertised TLS upgrade capability")] if cap else []
            ev.append(ev_event(s, used[0], "Cleartext command observed without TLS"))
            out.append(self.draft(
                title=f"{s.protocol.upper()} session continued in plaintext although TLS was offered", stream=s.stream_id, protocol=s.protocol.upper(),
                description="The server offered a TLS upgrade but the client did not use it.",
                technical=f"{CMD[s.protocol]} advertised; first cleartext command at frame {used[0].frame} ({used[0].summary}).",
                impact="Opportunistic encryption was not used: protocol commands (and any content) crossed the network unencrypted and could be read or altered by an on-path attacker.",
                observation_type="weakness_observed", completeness="complete", evidence=ev))
        return out


@register
class PlaintextAuth(Rule):
    meta = RuleMeta("SMS-STL-004", "Authentication attempted without TLS", "STARTTLS/STLS observations", "high",
        "An authentication command (AUTH / LOGIN / AUTHENTICATE / USER / PASS) was observed in a connection that was not protected by TLS.",
        "Authentication command observed before any TLS record in the stream (command is recorded, credential content is never stored).",
        "Authentication command frame (verb and mechanism only).",
        "Require TLS before authentication: disable plaintext AUTH/LOGIN (e.g. IMAP LOGINDISABLED, Postfix smtpd_tls_auth_only=yes) and rotate any credentials that may have crossed the network.",
        references=("RFC 8314", "RFC 4954 §4"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for s in ctx.sessions:
            if not s.auth_events:
                continue
            e = s.auth_events[0]
            out.append(self.draft(
                title=f"{s.protocol.upper()} authentication observed without TLS", stream=s.stream_id, protocol=s.protocol.upper(),
                description="Authentication was attempted over a connection that had not been upgraded to TLS.",
                technical=f"{len(s.auth_events)} authentication command(s); first at frame {e.frame}: {e.summary}. Credential data was not stored.",
                impact="Depending on the mechanism, credentials may be recoverable by anyone able to capture this traffic (PLAIN/LOGIN are base64, not encrypted).",
                observation_type="weakness_observed", completeness="complete",
                evidence=[ev_event(s, a, "Cleartext authentication command") for a in s.auth_events[:5]]))
        return out
