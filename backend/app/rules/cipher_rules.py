"""Cipher-suite rules driven by the IANA catalogue (unknown suites are never flagged)."""

from __future__ import annotations

from app.services.cipher_catalog import SIGNALLING, WEAK_EXPLANATION, WEAK_SEVERITY, classify, version_name
from app.services.models import AnalysisContext

from .base import Rule, RuleMeta, ev_tls
from .registry import register


@register
class WeakCipherSelected(Rule):
    meta = RuleMeta("SMS-CIP-001", "Legacy/weak cipher suite selected", "Legacy cipher suites", "high",
        "The server selected a cipher suite built on NULL, EXPORT, anonymous, RC4, DES, 3DES or MD5 primitives.",
        "Selected cipher (ServerHello) classified weak by the catalogue (weak_class != None).",
        "ServerHello frame.", "Restrict the server's cipher list to AEAD suites (AES-GCM / ChaCha20-Poly1305) with ECDHE key exchange; remove RC4, DES/3DES, EXPORT, NULL and anonymous suites.",
        references=("RFC 7465", "RFC 9325", "CVE-2016-2183"))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            if t.selected_cipher is None:
                continue
            ci = classify(t.selected_cipher)
            if not ci.is_weak:
                continue
            out.append(self.draft(
                title=f"Weak cipher suite selected: {ci.name}", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                severity=WEAK_SEVERITY[ci.weak_class],
                description=f"The negotiated cipher suite {ci.name} is considered weak ({ci.weak_class.upper()} class).",
                technical=f"ServerHello (frame {t.server_hello_frame}) selected 0x{ci.id:04X} {ci.name}. {WEAK_EXPLANATION[ci.weak_class]}",
                impact="Traffic protected with this suite can be decrypted or forged by a capable attacker.",
                observation_type="weakness_observed", completeness=t.completeness,
                evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello selected weak cipher suite",
                                 {"tls.handshake.type": "ServerHello", "selected_cipher": f"0x{ci.id:04X} {ci.name}", "weak_class": ci.weak_class}, "server->client", t.completeness)],
                detail={"cipher": ci.name, "weak_class": ci.weak_class}))
        return out


@register
class WeakCipherOffered(Rule):
    meta = RuleMeta("SMS-CIP-002", "Weak cipher suites offered by client", "Legacy cipher suites", "low",
        "The ClientHello offered weak suites that were not the ones selected.",
        "ClientHello offers at least one weak-class suite other than the selected suite.",
        "ClientHello frame (offered list).", "Remove weak suites from the client's cipher list.", references=("RFC 9325",))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            weak = [classify(c) for c in t.offered_ciphers if c not in SIGNALLING and classify(c).is_weak and c != t.selected_cipher]
            if not t.client_hello_frame or not weak:
                continue
            names = [w.name for w in weak]
            out.append(self.draft(
                title=f"Client offered {len(weak)} weak cipher suite(s)", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                description="Weak suites were offered. This is an offer, not a negotiated weakness (the server chose otherwise or the choice is unknown).",
                technical="Weak suites offered: " + ", ".join(names[:12]) + ("…" if len(names) > 12 else ""),
                impact="A server (or downgrade attacker) willing to select one of these would weaken the session.",
                observation_type="weak_option_offered", completeness=t.completeness,
                evidence=[ev_tls(t, t.client_hello_frame, t.client_hello_ts, "ClientHello cipher-suite list",
                                 {"tls.handshake.type": "ClientHello", "offered_weak": names[:20], "offered_total": len(t.offered_ciphers)}, "client->server", t.completeness)],
                detail={"weak_offered": names}))
        return out


@register
class NoForwardSecrecy(Rule):
    meta = RuleMeta("SMS-CIP-003", "Cipher suite without forward secrecy selected", "Weak cryptographic algorithms", "medium",
        "A static key-exchange suite (RSA / static ECDH) was selected for a pre-TLS-1.3 session.",
        "Selected suite is known and forward_secret is False (version < TLS 1.3).",
        "ServerHello frame.", "Prefer ECDHE/DHE suites so past traffic stays protected if the server key is later compromised.", references=("RFC 9325 §4.1",))

    def evaluate(self, ctx: AnalysisContext):
        out = []
        for t in ctx.tls_sessions:
            if t.selected_cipher is None or t.tls13:
                continue
            ci = classify(t.selected_cipher)
            if ci.known and ci.forward_secret is False and not ci.signalling:
                out.append(self.draft(
                    title=f"No forward secrecy: {ci.name}", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description="The negotiated suite uses static key exchange.",
                    technical=f"ServerHello (frame {t.server_hello_frame}) selected {ci.name} under {version_name(t.selected_version)}.",
                    impact="If the server's private key is ever compromised, recorded sessions can be decrypted retroactively.",
                    observation_type="weakness_observed", completeness=t.completeness,
                    evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello selected static-key-exchange suite",
                                     {"selected_cipher": f"0x{ci.id:04X} {ci.name}", "forward_secret": False}, "server->client", t.completeness)]))
        return out
