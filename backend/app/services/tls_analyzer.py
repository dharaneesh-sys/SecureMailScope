"""TLS handshake observation extraction from TShark's TLS dissection.

Handles the TLS 1.3 subtleties that commonly cause wrong results:

* ``handshake.version`` in a TLS 1.3 hello is the *legacy* field (0x0303). The
  negotiated version comes from the ``supported_versions`` extension of the
  ServerHello.
* After the ServerHello of a TLS 1.3 session the Certificate message is
  encrypted, so certificate data is reported as *unavailable*, never guessed.
"""

from __future__ import annotations

from .certificate_analyzer import parse_chain
from .frames import FrameMeta, find_all, find_first, hex_int
from .models import EmailSessionObs, StreamInfo, TlsSessionObs
from .tshark_runner import as_list

EXT_ECH = 0xFE0D
SIGALG_NAMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1", 0x0401: "rsa_pkcs1_sha256", 0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384", 0x0503: "ecdsa_secp384r1_sha384", 0x0601: "rsa_pkcs1_sha512", 0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
}
GROUP_NAMES = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x11EC: "X25519MLKEM768"}


def _records(tls: dict) -> list[dict]:
    return [r for r in as_list(tls.get("tls.record")) if isinstance(r, dict)]


def _handshakes(rec: dict) -> list[dict]:
    return [h for h in as_list(rec.get("tls.handshake")) if isinstance(h, dict)]


def _ext_types(hs: dict) -> list[int]:
    out = []
    for e in as_list(hs.get("tls.handshake.extension")):
        if isinstance(e, dict):
            t = e.get("tls.handshake.extension.type")
            if t is not None:
                try:
                    out.append(int(t))
                except ValueError:
                    pass
    return out


def analyze_tls(
    stream: StreamInfo,
    frames: list[tuple[FrameMeta, dict]],
    session: EmailSessionObs | None,
) -> TlsSessionObs | None:
    """Build one TLS session observation from the stream's TLS-bearing frames."""
    t = TlsSessionObs(
        stream_id=stream.stream_id,
        client_ip=stream.client_ip, client_port=stream.client_port,
        server_ip=stream.server_ip, server_port=stream.server_port,
        carrier_protocol=stream.protocol or "tls-direct",
        via_starttls=bool(session and session.starttls_accepted),
    )
    any_tls = False
    for meta, layers in frames:
        tls = layers.get("tls")
        if not isinstance(tls, dict):
            continue
        any_tls = True
        t.frames.append(meta.number)
        t.first_ts = meta.ts if t.first_ts is None else t.first_ts
        direction_c2s = (meta.src, meta.sport) == (stream.client_ip, stream.client_port)
        for rec in _records(tls):
            rv = hex_int(rec.get("tls.record.version"))
            if rv is not None:
                name = f"0x{rv:04x}"
                if name not in t.record_versions:
                    t.record_versions.append(name)
            ctype = rec.get("tls.record.content_type") or rec.get("tls.record.opaque_type")
            ctype_i = int(ctype) if ctype not in (None, "") and str(ctype).isdigit() else None
            if "tls.change_cipher_spec" in rec or ctype_i == 20:
                t.change_cipher_spec_seen = True
            if ctype_i == 21 or "tls.alert_message" in rec:
                lvl = find_first(rec, "tls.alert_message.desc")
                t.alerts.append(f"alert {lvl}" if lvl else "alert")
            if "tls.app_data" in rec or ctype_i == 23:
                t.encrypted_after_hello = True
            for hs in _handshakes(rec):
                htype = hs.get("tls.handshake.type")
                if htype is None:
                    t.encrypted_after_hello = True  # encrypted handshake record we cannot read
                    continue
                htype = int(htype)
                if htype == 1 and direction_c2s and t.client_hello_frame is None:
                    t.client_hello_frame, t.client_hello_ts = meta.number, meta.ts
                    t.client_legacy_version = hex_int(hs.get("tls.handshake.version"))
                    t.offered_ciphers = [c for c in (hex_int(x) for x in find_all(hs, "tls.handshake.ciphersuite")) if c is not None]
                    t.extensions_offered = _ext_types(hs)
                    t.ech_seen = EXT_ECH in t.extensions_offered
                    t.sni = find_first(hs, "tls.handshake.extensions_server_name")
                    t.alpn = find_all(hs, "tls.handshake.extensions_alpn_str")
                    t.supported_groups = [GROUP_NAMES.get(g, f"0x{g:04x}") for g in (hex_int(x) for x in find_all(hs, "tls.handshake.extensions_supported_group")) if g is not None]
                    t.signature_algorithms = [SIGALG_NAMES.get(g, f"0x{g:04x}") for g in (hex_int(x) for x in find_all(hs, "tls.handshake.sig_hash_alg")) if g is not None]
                    t.client_supported_versions = [v for v in (hex_int(x) for x in find_all(hs, "tls.handshake.extensions.supported_version")) if v is not None]
                elif htype == 2 and not direction_c2s and t.server_hello_frame is None:
                    t.server_hello_frame, t.server_hello_ts = meta.number, meta.ts
                    t.server_legacy_version = hex_int(hs.get("tls.handshake.version"))
                    t.selected_cipher = hex_int(hs.get("tls.handshake.ciphersuite"))
                    t.server_extensions = _ext_types(hs)
                    sv = hex_int(find_first(hs, "tls.handshake.extensions.supported_version"))
                    if sv is not None:
                        t.selected_version, t.selected_version_source = sv, "supported_versions"
                    else:
                        t.selected_version, t.selected_version_source = t.server_legacy_version, "server_version"
                elif htype == 11 and not direction_c2s and not t.certificates:
                    t.certificate_frame = meta.number
                    ders = []
                    for x in find_all(hs, "tls.handshake.certificate"):
                        try:
                            ders.append(bytes.fromhex(x.replace(":", "")))
                        except ValueError:
                            pass
                    t.certificates = parse_chain(ders, stream.stream_id, meta.number, meta.ts)
                elif htype == 12:
                    t.server_key_exchange = True
                elif htype == 14:
                    t.server_hello_done = True
    if not any_tls:
        return None
    if t.tls13:
        t.notes.append("TLS 1.3 negotiated: the server Certificate message is encrypted and not visible without decryption material.")
    if t.ech_seen:
        t.notes.append("Encrypted Client Hello extension observed: the true inner ClientHello (SNI, ALPN) is not visible.")
    return t
