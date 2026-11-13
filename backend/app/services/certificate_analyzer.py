"""X.509 *metadata extraction* from certificates visible in the capture.

This module reports what the certificate says. It performs **no trust
validation** (no chain building against a trust store, no revocation check);
the UI and reports state this explicitly.
"""

from __future__ import annotations

import datetime as dt
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from .models import CertObs

_SIG_HASH_BY_OID = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "sha256"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "sha384"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "sha512"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "sha512"),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
}


def _name(n: x509.Name) -> str:
    return n.rfc4514_string() or "(empty)"


def parse_der(der: bytes, stream_id: int, position: int, frame: int | None, ts: float | None) -> CertObs | None:
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    oid = c.signature_algorithm_oid.dotted_string
    sig_name, sig_hash = _SIG_HASH_BY_OID.get(oid, (c.signature_algorithm_oid._name if hasattr(c.signature_algorithm_oid, "_name") else oid, None))
    if sig_hash is None:
        try:
            alg = c.signature_hash_algorithm
            sig_hash = alg.name if alg else None
        except Exception:
            sig_hash = None
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        ka, ks = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        ka, ks = f"EC ({pk.curve.name})", pk.key_size
    elif isinstance(pk, dsa.DSAPublicKey):
        ka, ks = "DSA", pk.key_size
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        ka, ks = "Ed25519", 256
    elif isinstance(pk, ed448.Ed448PublicKey):
        ka, ks = "Ed448", 456
    else:
        ka, ks = type(pk).__name__, None
    san: list[str] = []
    try:
        ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    is_ca = None
    try:
        is_ca = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass
    nb = c.not_valid_before_utc
    na = c.not_valid_after_utc
    return CertObs(
        stream_id=stream_id,
        position=position,
        frame=frame,
        subject=_name(c.subject),
        issuer=_name(c.issuer),
        serial=format(c.serial_number, "x"),
        not_before=nb.isoformat(),
        not_after=na.isoformat(),
        sig_algorithm=sig_name,
        sig_hash=sig_hash,
        key_algorithm=ka,
        key_size=ks,
        san=san,
        sha256=c.fingerprint(hashes.SHA256()).hex(),
        self_signed=c.subject == c.issuer,
        is_ca=is_ca,
        der_len=len(der),
        ts=ts,
    )


def parse_chain(ders: Iterable[bytes], stream_id: int, frame: int | None, ts: float | None) -> list[CertObs]:
    out = []
    for i, d in enumerate(ders):
        c = parse_der(d, stream_id, i, frame, ts)
        if c:
            out.append(c)
    return out


def name_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.split(".", 1)[1:] == pattern.split(".", 1)[1:]
    return host == pattern


def parse_iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)
