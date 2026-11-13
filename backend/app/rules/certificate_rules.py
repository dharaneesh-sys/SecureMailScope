"""Certificate *metadata* rules. None of these assert trust or distrust."""

from __future__ import annotations

import datetime as dt

from app.services.certificate_analyzer import name_matches, parse_iso
from app.services.models import AnalysisContext, CertObs, TlsSessionObs

from .base import Rule, RuleMeta, ev_tls
from .registry import register


def _ref(ctx: AnalysisContext, c: CertObs) -> dt.datetime | None:
    ts = c.ts if c.ts is not None else ctx.cert_reference_ts
    if ts is None:
        return None
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc)


def _cert_ev(t: TlsSessionObs, c: CertObs, what: str):
    return ev_tls(t, c.frame, c.ts, what, {"certificate.subject": c.subject, "certificate.issuer": c.issuer, "certificate.position": c.position,
                                           "certificate.sha256": c.sha256}, "server->client", "complete")


class _CertRule(Rule):
    def per_cert(self, ctx: AnalysisContext, leaf_only: bool = False):
        for t in ctx.tls_sessions:
            for c in t.certificates:
                if leaf_only and c.position != 0:
                    continue
                yield t, c


@register
class CertExpired(_CertRule):
    meta = RuleMeta("SMS-CRT-001", "Expired certificate observed", "Certificate issues", "high",
        "A certificate presented in the handshake was past its notAfter date at the time of capture.",
        "notAfter < reference time (capture timestamp of the Certificate message).", "Certificate message frame.",
        "Renew and deploy a valid certificate; monitor expiry.", references=("RFC 5280 §4.1.2.5",))

    def evaluate(self, ctx):
        out = []
        for t, c in self.per_cert(ctx):
            ref = _ref(ctx, c)
            if ref and parse_iso(c.not_after) < ref:
                out.append(self.draft(title="Expired certificate presented" + ("" if c.position == 0 else f" (chain position {c.position})"), stream=t.stream_id,
                    protocol=(t.carrier_protocol or "TLS").upper(), description=f"Certificate '{c.subject}' expired on {c.not_after[:10]}.",
                    technical=f"notAfter={c.not_after}, reference (capture) time={ref.isoformat()}.", impact="Clients will reject or warn on this certificate; users may be trained to click through warnings, enabling interception.",
                    observation_type="weakness_observed", completeness="complete", evidence=[_cert_ev(t, c, "Certificate with elapsed notAfter")]))
        return out


@register
class CertNotYetValid(_CertRule):
    meta = RuleMeta("SMS-CRT-002", "Certificate not yet valid", "Certificate issues", "medium",
        "A certificate's notBefore date was later than the capture time.", "notBefore > reference time.", "Certificate message frame.",
        "Check server clock and certificate issuance dates.", references=("RFC 5280 §4.1.2.5",))

    def evaluate(self, ctx):
        out = []
        for t, c in self.per_cert(ctx):
            ref = _ref(ctx, c)
            if ref and parse_iso(c.not_before) > ref:
                out.append(self.draft(title="Certificate not yet valid", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description=f"Certificate '{c.subject}' becomes valid on {c.not_before[:10]}.", technical=f"notBefore={c.not_before}, reference time={ref.isoformat()}.",
                    impact="May indicate a misconfigured clock on the server or the capture host.", observation_type="weakness_observed", completeness="complete",
                    evidence=[_cert_ev(t, c, "Certificate with future notBefore")]))
        return out


@register
class CertWeakSignature(_CertRule):
    meta = RuleMeta("SMS-CRT-003", "Weak certificate signature algorithm", "Weak cryptographic algorithms", "medium",
        "A certificate is signed with MD5 or SHA-1.", "signature hash in {md5, sha1} for the leaf or an intermediate (self-signed trust anchors are exempt).",
        "Certificate message frame.", "Re-issue the certificate with SHA-256 or stronger.", references=("RFC 9155", "CA/B Forum Baseline Requirements"))

    def evaluate(self, ctx):
        out = []
        for t, c in self.per_cert(ctx):
            if c.sig_hash in ("md5", "sha1") and not (c.self_signed and c.position > 0):
                out.append(self.draft(title=f"Certificate signed with {c.sig_hash.upper()}", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    severity="high" if c.sig_hash == "md5" else None, description=f"Signature algorithm {c.sig_algorithm} is considered weak.",
                    technical=f"signatureAlgorithm={c.sig_algorithm} on '{c.subject}'.", impact="Collision attacks make forged certificates feasible against weak hash functions.",
                    observation_type="weakness_observed", completeness="complete", evidence=[_cert_ev(t, c, "Certificate with weak signature hash")]))
        return out


@register
class CertWeakKey(_CertRule):
    meta = RuleMeta("SMS-CRT-004", "Weak certificate public key", "Weak cryptographic algorithms", "medium",
        "A certificate public key is shorter than current minimums (RSA/DSA < 2048 bits, EC < 224 bits).",
        "RSA/DSA key_size < 2048 or EC key_size < 224 on the leaf or intermediates.", "Certificate message frame.",
        "Issue a new certificate with an RSA >= 2048 (3072 recommended) or P-256+ EC key.", references=("NIST SP 800-57", "NIST SP 800-131A"))

    def evaluate(self, ctx):
        out = []
        for t, c in self.per_cert(ctx):
            if c.key_size is None:
                continue
            weak = (c.key_algorithm in ("RSA", "DSA") and c.key_size < 2048) or (c.key_algorithm.startswith("EC") and c.key_size < 224)
            if weak:
                sev = "high" if c.key_size <= 1024 else "medium"
                out.append(self.draft(title=f"Weak {c.key_algorithm} key ({c.key_size} bits)", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(), severity=sev,
                    description=f"The certificate public key is {c.key_algorithm} {c.key_size}-bit.", technical=f"subjectPublicKeyInfo: {c.key_algorithm} {c.key_size} bits on '{c.subject}'.",
                    impact="Short keys can be factored or brute-forced with feasible resources, allowing impersonation or decryption.",
                    observation_type="weakness_observed", completeness="complete", evidence=[_cert_ev(t, c, "Certificate with short public key")]))
        return out


@register
class CertEvidenceUnavailable(Rule):
    meta = RuleMeta("SMS-CRT-005", "Certificate evidence unavailable", "Certificate issues", "info",
        "No certificate could be extracted: it is encrypted (TLS 1.3), absent from the capture, or the session was resumed.",
        "Server hello observed AND no Certificate message extracted.", "ServerHello frame.", "Capture a full handshake, or provide authorised key-log material in a lab setting.")

    def evaluate(self, ctx):
        out = []
        for t in ctx.tls_sessions:
            if not t.server_hello_frame or t.certificates:
                continue
            reason = "TLS 1.3 encrypts the Certificate message after the ServerHello" if t.tls13 else "no Certificate message was present in the captured handshake (session resumption or truncated capture)"
            out.append(self.draft(title="Certificate details not observable", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                description="Certificate checks were not performed. " + reason + ".", technical=f"ServerHello at frame {t.server_hello_frame}; no readable Certificate handshake message.",
                impact="Expiry, key-strength and signature checks could not run. This is not evidence of a problem.", observation_type="insufficient_evidence",
                completeness="partial", evidence=[ev_tls(t, t.server_hello_frame, t.server_hello_ts, "ServerHello (no readable Certificate follows)", {"tls_version": t.selected_version_source}, "server->client", "partial")]))
        return out


@register
class CertSelfSigned(_CertRule):
    meta = RuleMeta("SMS-CRT-006", "Self-signed leaf certificate", "Certificate issues", "low",
        "The server's leaf certificate has identical subject and issuer. No trust-store validation was performed.",
        "leaf.subject == leaf.issuer.", "Certificate message frame.", "Use a certificate issued by a CA trusted by your clients, or pin the certificate deliberately.")

    def evaluate(self, ctx):
        out = []
        for t, c in self.per_cert(ctx, leaf_only=True):
            if c.self_signed:
                out.append(self.draft(title="Self-signed leaf certificate", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description=f"'{c.subject}' is its own issuer.", technical="subject == issuer. SecureMailScope does not evaluate trust; a self-signed certificate can be legitimate for private deployments.",
                    impact="Clients cannot authenticate the server through a CA chain; clients that accept it blindly are vulnerable to impersonation.",
                    observation_type="protocol_feature", completeness="complete", evidence=[_cert_ev(t, c, "Leaf certificate with subject == issuer")]))
        return out


@register
class CertChainLacksIssuer(_CertRule):
    meta = RuleMeta("SMS-CRT-007", "Presented chain lacks issuer certificate", "Certificate issues", "low",
        "Only the leaf certificate was presented and its issuer is not included. Clients lacking the intermediate may fail validation.",
        "exactly one certificate in the Certificate message AND leaf is not self-signed. (Observation about the chain *as presented*, not a trust decision.)",
        "Certificate message frame.", "Configure the server to send the full chain (leaf + intermediates).")

    def evaluate(self, ctx):
        out = []
        for t in ctx.tls_sessions:
            if len(t.certificates) == 1 and not t.certificates[0].self_signed:
                c = t.certificates[0]
                out.append(self.draft(title="Certificate chain presented without intermediate", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description="Only the leaf certificate was sent.", technical=f"1 certificate in message; issuer '{c.issuer}' not included.",
                    impact="Some clients cannot build a path to a trust anchor. Whether the chain is trusted was NOT evaluated.", observation_type="protocol_feature",
                    completeness="complete", evidence=[_cert_ev(t, c, "Single certificate in Certificate message")]))
        return out


@register
class CertNameMismatch(_CertRule):
    meta = RuleMeta("SMS-CRT-008", "Leaf certificate does not match SNI", "Certificate issues", "medium",
        "The ClientHello SNI is not covered by the leaf certificate's SAN/CN.",
        "SNI visible AND leaf has SAN or CN AND no SAN/CN matches the SNI (RFC 6125 wildcard rules).", "ClientHello and Certificate frames.",
        "Issue a certificate whose SAN covers the host name clients use.", references=("RFC 6125",))

    def evaluate(self, ctx):
        out = []
        for t in ctx.tls_sessions:
            if not t.sni or not t.certificates:
                continue
            c = t.certificates[0]
            names = list(c.san)
            if not names:
                cn = next((p.split("=", 1)[1] for p in c.subject.split(",") if p.startswith("CN=")), None)
                names = [cn] if cn else []
            if names and not any(name_matches(t.sni, n) for n in names):
                out.append(self.draft(title="Certificate does not match requested server name", stream=t.stream_id, protocol=(t.carrier_protocol or "TLS").upper(),
                    description=f"Client requested '{t.sni}' but the certificate names are: {', '.join(names)}.", technical=f"SNI={t.sni}; SAN/CN={names}.",
                    impact="Clients performing hostname verification will reject the connection; clients that skip it are exposed to impersonation.",
                    observation_type="weakness_observed", completeness="complete", evidence=[_cert_ev(t, c, "Leaf certificate names"),
                    ev_tls(t, t.client_hello_frame, t.client_hello_ts, "ClientHello SNI", {"sni": t.sni}, "client->server")]))
        return out
