"""Synthetic PCAP fixture generator for SecureMailScope.

Every capture produced here is CONTROLLED SYNTHETIC DATA (RFC 5737 documentation
addresses, ``.test`` domains, throw-away keys). Nothing is derived from real traffic.

The TLS records are hand-assembled so that Wireshark/TShark dissects them as real
handshake messages; encrypted portions after the hello exchange are random bytes.

Run directly to (re)generate the captures and ``manifest.json``::

    python backend/tests/fixtures/generate.py sample_data/authorised_demo_captures
"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --------------------------------------------------------------------------- crypto
CS = {
    "ECDHE_RSA_AES256_GCM_SHA384": 0xC030,
    "ECDHE_RSA_AES128_GCM_SHA256": 0xC02F,
    "ECDHE_RSA_CHACHA20": 0xCCA8,
    "RSA_AES256_CBC_SHA": 0x0035,
    "RSA_3DES_EDE_CBC_SHA": 0x000A,
    "RSA_RC4_128_SHA": 0x0005,
    "RSA_RC4_128_MD5": 0x0004,
    "RSA_EXPORT_RC4_40_MD5": 0x0003,
    "RSA_NULL_SHA": 0x0002,
    "TLS13_AES_128_GCM_SHA256": 0x1301,
    "TLS13_AES_256_GCM_SHA384": 0x1302,
    "TLS13_CHACHA20_POLY1305": 0x1303,
}
VER = {"SSL3": 0x0300, "TLS10": 0x0301, "TLS11": 0x0302, "TLS12": 0x0303, "TLS13": 0x0304}


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    cn: str,
    *,
    key_bits: int = 2048,
    sig_hash=hashes.SHA256,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    issuer_key=None,
    issuer_cn: str | None = None,
    san: list[str] | None = None,
    ca: bool = False,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    # Fixed validity window around BASE_TS (2026-01-01) so fixtures are reproducible.
    nb = not_before or dt.datetime(2025, 12, 1, tzinfo=dt.timezone.utc)
    na = not_after or dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False
        )
    if sig_hash is hashes.SHA1:
        # Modern OpenSSL builds refuse to sign with SHA-1. For this synthetic fixture we
        # sign with SHA-256 and rewrite sha256WithRSAEncryption -> sha1WithRSAEncryption
        # (same DER length) in both signature-algorithm fields. The signature bytes are
        # therefore not valid, which is irrelevant: SecureMailScope never trusts them.
        cert = builder.sign(issuer_key or key, hashes.SHA256())
        patched = der(cert).replace(bytes.fromhex("2a864886f70d01010b"), bytes.fromhex("2a864886f70d010105"))
        return key, x509.load_der_x509_certificate(patched)
    cert = builder.sign(issuer_key or key, sig_hash())
    return key, cert


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- TLS
def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _ext(t: int, body: bytes) -> bytes:
    return _u16(t) + _u16(len(body)) + body


def hs(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + _u24(len(body)) + body


def record(ctype: int, version: int, body: bytes) -> bytes:
    return bytes([ctype]) + _u16(version) + _u16(len(body)) + body


def client_hello(
    *,
    legacy_version: int,
    ciphers: list[int],
    sni: str | None,
    supported_versions: list[int] | None = None,
    rng: random.Random,
) -> bytes:
    exts = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + _u16(len(name)) + name
        exts += _ext(0, _u16(len(entry)) + entry)
    groups = [0x001D, 0x0017, 0x0018]
    exts += _ext(10, _u16(len(groups) * 2) + b"".join(_u16(g) for g in groups))
    exts += _ext(11, b"\x01\x00")
    sigalgs = [0x0804, 0x0401, 0x0403, 0x0201]
    exts += _ext(13, _u16(len(sigalgs) * 2) + b"".join(_u16(s) for s in sigalgs))
    alpn = b"\x08http/1.1"
    exts += _ext(16, _u16(len(alpn)) + alpn)
    if supported_versions:
        exts += _ext(43, bytes([len(supported_versions) * 2]) + b"".join(_u16(v) for v in supported_versions))
        share = _u16(0x001D) + _u16(32) + rng.randbytes(32)
        exts += _ext(51, _u16(len(share)) + share)
    body = (
        _u16(legacy_version)
        + rng.randbytes(32)
        + b"\x00"
        + _u16(len(ciphers) * 2)
        + b"".join(_u16(c) for c in ciphers)
        + b"\x01\x00"
        + _u16(len(exts))
        + exts
    )
    return hs(1, body)


def server_hello(*, version: int, cipher: int, tls13: bool, rng: random.Random) -> bytes:
    exts = b""
    if tls13:
        exts += _ext(43, _u16(VER["TLS13"]))
        exts += _ext(51, _u16(0x001D) + _u16(32) + rng.randbytes(32))
        sid = b"\x00"
        version = VER["TLS12"]  # legacy_version
    else:
        exts += _ext(0xFF01, b"\x00")  # renegotiation_info
        sid = b"\x20" + rng.randbytes(32)
    body = _u16(version) + rng.randbytes(32) + sid + _u16(cipher) + b"\x00" + _u16(len(exts)) + exts
    return hs(2, body)


def certificate_msg(certs: list[bytes]) -> bytes:
    lst = b"".join(_u24(len(c)) + c for c in certs)
    return hs(11, _u24(len(lst)) + lst)


def server_key_exchange(rng: random.Random) -> bytes:
    pub = rng.randbytes(32)
    sig = rng.randbytes(256)
    body = b"\x03" + _u16(0x001D) + bytes([len(pub)]) + pub + _u16(0x0804) + _u16(len(sig)) + sig
    return hs(12, body)


# --------------------------------------------------------------------------- packets
def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(src: str, dst: str) -> tuple[bytes, bytes]:
    return bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split("."))


def build_frame(src, dst, sport, dport, seq, ack, flags, payload=b"", ident=1) -> bytes:
    s, d = _ip(src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    c = _csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    iph = struct.pack("!BBHHHBBH", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, 6, 0) + s + d
    iph = iph[:10] + struct.pack("!H", _csum(iph)) + iph[12:]
    eth = bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00"
    return eth + iph + tcp + payload


@dataclass
class Frame:
    ts: float
    data: bytes
    is_data: bool = False
    direction: str = ""


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Flow:
    client: str
    server: str
    cport: int
    sport: int
    t0: float
    mss: int = 1400
    frames: list[Frame] = field(default_factory=list)
    _t: float = 0.0
    _cseq: int = 1000
    _sseq: int = 5000
    _ident: int = 1

    def __post_init__(self):
        self._t = self.t0
        self._emit("c", SYN, b"", self._cseq, 0)
        self._cseq += 1
        self._emit("s", SYN | ACK, b"", self._sseq, self._cseq)
        self._sseq += 1
        self._emit("c", ACK, b"", self._cseq, self._sseq)

    def _emit(self, who: str, flags: int, payload: bytes, seq: int, ack: int, is_data=False):
        self._t += 0.0007
        self._ident += 1
        if who == "c":
            raw = build_frame(self.client, self.server, self.cport, self.sport, seq, ack, flags, payload, self._ident)
        else:
            raw = build_frame(self.server, self.client, self.sport, self.cport, seq, ack, flags, payload, self._ident)
        self.frames.append(Frame(self._t, raw, is_data, who))

    def send(self, who: str, data: bytes, split: int | None = None):
        step = split or self.mss
        for i in range(0, len(data), step):
            chunk = data[i : i + step]
            if who == "c":
                self._emit("c", PSH | ACK, chunk, self._cseq, self._sseq, True)
                self._cseq += len(chunk)
                self._emit("s", ACK, b"", self._sseq, self._cseq)
            else:
                self._emit("s", PSH | ACK, chunk, self._sseq, self._cseq, True)
                self._sseq += len(chunk)
                self._emit("c", ACK, b"", self._cseq, self._sseq)

    def close(self):
        self._emit("c", FIN | ACK, b"", self._cseq, self._sseq)
        self._cseq += 1
        self._emit("s", FIN | ACK, b"", self._sseq, self._cseq)
        self._sseq += 1
        self._emit("c", ACK, b"", self._cseq, self._sseq)

    # impairments -----------------------------------------------------------
    def duplicate_data_frame(self, nth: int):
        data_frames = [f for f in self.frames if f.is_data]
        f = data_frames[nth]
        idx = self.frames.index(f)
        self.frames.insert(idx + 3, Frame(f.ts + 0.2, f.data, True, f.direction))

    def swap_data_frames(self, a: int, b: int):
        """Swap payload order of two data frames while keeping timestamps monotonic."""
        idxs = [i for i, f in enumerate(self.frames) if f.is_data]
        ia, ib = idxs[a], idxs[b]
        fa, fb = self.frames[ia], self.frames[ib]
        self.frames[ia] = Frame(fa.ts, fb.data, True, fb.direction)
        self.frames[ib] = Frame(fb.ts, fa.data, True, fa.direction)

    def drop_data_frame(self, nth: int):
        data_frames = [f for f in self.frames if f.is_data]
        self.frames.remove(data_frames[nth])

    def truncate_after_data(self, nth: int):
        """Keep frames up to and including the nth data frame (capture stopped early)."""
        data_frames = [f for f in self.frames if f.is_data]
        idx = self.frames.index(data_frames[nth])
        self.frames = self.frames[: idx + 1]


def write_pcap(path: Path, frames: list[Frame], linktype: int = 1):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for f in sorted(frames, key=lambda x: x.ts):
            sec = int(f.ts)
            usec = int((f.ts - sec) * 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(f.data), len(f.data)))
            fh.write(f.data)


# --------------------------------------------------------------------------- scenarios
CLIENT = "192.0.2.10"
SERVER = "198.51.100.25"
MAIL = "mail.example.test"
BASE_TS = 1_767_225_600.0  # 2026-01-01T00:00:00Z

_state: dict = {}


def _ca():
    if "ca" not in _state:
        _state["ca"] = make_cert("SecureMailScope Synthetic Test CA", ca=True, not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc), not_after=dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc))
    return _state["ca"]


def good_chain() -> list[bytes]:
    ca_key, ca_cert = _ca()
    _, leaf = make_cert(MAIL, issuer_key=ca_key, issuer_cn="SecureMailScope Synthetic Test CA", san=[MAIL])
    return [der(leaf), der(ca_cert)]


def tls12_server_flight(version: int, cipher: int, chain: list[bytes] | None, rng, ecdhe: bool) -> bytes:
    msgs = server_hello(version=version, cipher=cipher, tls13=False, rng=rng)
    if chain:
        msgs += certificate_msg(chain)
    if ecdhe:
        msgs += server_key_exchange(rng)
    msgs += hs(14, b"")
    return record(22, version, msgs)


def run_tls(
    flow: Flow,
    rng: random.Random,
    *,
    legacy_version: int,
    offered: list[int],
    selected: int,
    sel_version: int,
    chain: list[bytes] | None,
    sni: str | None = MAIL,
    ecdhe: bool = True,
    tls13: bool = False,
    split: int | None = None,
):
    sv = [VER["TLS13"], VER["TLS12"]] if tls13 else None
    ch = client_hello(legacy_version=legacy_version, ciphers=offered, sni=sni, supported_versions=sv, rng=rng)
    flow.send("c", record(22, VER["TLS10"] if legacy_version >= VER["TLS10"] else legacy_version, ch), split)
    if tls13:
        sh = record(22, VER["TLS12"], server_hello(version=VER["TLS13"], cipher=selected, tls13=True, rng=rng))
        sh += record(20, VER["TLS12"], b"\x01")
        sh += record(23, VER["TLS12"], rng.randbytes(900))  # encrypted EncryptedExtensions/Certificate/Finished
        flow.send("s", sh, split)
        flow.send("c", record(20, VER["TLS12"], b"\x01") + record(23, VER["TLS12"], rng.randbytes(60)), split)
        flow.send("s", record(23, VER["TLS12"], rng.randbytes(180)), split)
    else:
        flow.send("s", tls12_server_flight(sel_version, selected, chain, rng, ecdhe), split)
        flow.send("c", record(20, sel_version, b"\x01") + record(22, sel_version, rng.randbytes(40)), split)
        flow.send("s", record(20, sel_version, b"\x01") + record(22, sel_version, rng.randbytes(40)), split)
        flow.send("c", record(23, sel_version, rng.randbytes(120)), split)


def smtp_prelude(flow: Flow, *, advertise_starttls=True, reject=False):
    flow.send("s", f"220 {MAIL} ESMTP Postfix\r\n".encode())
    flow.send("c", b"EHLO client.example.test\r\n")
    caps = ["250-" + MAIL, "250-PIPELINING", "250-SIZE 10240000"]
    if advertise_starttls:
        caps.append("250-STARTTLS")
    caps += ["250-AUTH PLAIN LOGIN", "250 8BITMIME"]
    flow.send("s", ("\r\n".join(caps) + "\r\n").encode())
    flow.send("c", b"STARTTLS\r\n")
    if reject:
        flow.send("s", b"454 4.7.0 TLS not available due to local problem\r\n")
    else:
        flow.send("s", b"220 2.0.0 Ready to start TLS\r\n")


def imap_prelude(flow: Flow):
    flow.send("s", b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] IMAP server ready\r\n")
    flow.send("c", b"a001 CAPABILITY\r\n")
    flow.send("s", b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK CAPABILITY completed\r\n")
    flow.send("c", b"a002 STARTTLS\r\n")
    flow.send("s", b"a002 OK Begin TLS negotiation now\r\n")


def pop3_prelude(flow: Flow):
    flow.send("s", b"+OK POP3 server ready\r\n")
    flow.send("c", b"CAPA\r\n")
    flow.send("s", b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n")
    flow.send("c", b"STLS\r\n")
    flow.send("s", b"+OK Begin TLS negotiation\r\n")


MODERN_OFFER = [CS["ECDHE_RSA_AES256_GCM_SHA384"], CS["ECDHE_RSA_AES128_GCM_SHA256"], CS["ECDHE_RSA_CHACHA20"]]
LEGACY_OFFER = [CS["RSA_3DES_EDE_CBC_SHA"], CS["RSA_RC4_128_SHA"], CS["RSA_RC4_128_MD5"], CS["RSA_EXPORT_RC4_40_MD5"], CS["RSA_NULL_SHA"], CS["RSA_AES256_CBC_SHA"]]


def _seeded(name: str) -> random.Random:
    return random.Random(name)


def scenario_smtp_tls12_complete(out: Path):
    rng = _seeded("smtp12")
    f = Flow(CLIENT, SERVER, 49152, 25, BASE_TS)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=MODERN_OFFER, selected=CS["ECDHE_RSA_AES256_GCM_SHA384"], sel_version=VER["TLS12"], chain=good_chain())
    f.close()
    write_pcap(out, f.frames)


def scenario_smtp_missing_handshake(out: Path):
    f = Flow(CLIENT, SERVER, 49153, 25, BASE_TS + 10)
    smtp_prelude(f)
    f.close()
    write_pcap(out, f.frames)


def scenario_imap(out: Path):
    rng = _seeded("imap")
    f = Flow(CLIENT, SERVER, 49154, 143, BASE_TS + 20)
    imap_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=MODERN_OFFER, selected=CS["ECDHE_RSA_AES128_GCM_SHA256"], sel_version=VER["TLS12"], chain=good_chain())
    f.close()
    write_pcap(out, f.frames)


def scenario_pop3(out: Path):
    rng = _seeded("pop3")
    f = Flow(CLIENT, SERVER, 49155, 110, BASE_TS + 30)
    pop3_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=MODERN_OFFER, selected=CS["ECDHE_RSA_CHACHA20"], sel_version=VER["TLS12"], chain=good_chain())
    f.close()
    write_pcap(out, f.frames)


def scenario_deprecated_tls10(out: Path):
    rng = _seeded("tls10")
    old = dt.datetime(2018, 1, 1, tzinfo=dt.timezone.utc)
    _, cert = make_cert(MAIL, key_bits=1024, sig_hash=hashes.SHA1, not_before=old, not_after=dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc), san=[MAIL])
    f = Flow(CLIENT, SERVER, 49156, 25, BASE_TS + 40)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS10"], offered=LEGACY_OFFER, selected=CS["RSA_3DES_EDE_CBC_SHA"], sel_version=VER["TLS10"], chain=[der(cert)], ecdhe=False)
    f.close()
    write_pcap(out, f.frames)


def scenario_legacy_cipher_tls12(out: Path):
    rng = _seeded("rc4")
    f = Flow(CLIENT, SERVER, 49157, 25, BASE_TS + 50)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=LEGACY_OFFER + MODERN_OFFER, selected=CS["RSA_RC4_128_SHA"], sel_version=VER["TLS12"], chain=good_chain(), ecdhe=False)
    f.close()
    write_pcap(out, f.frames)


def scenario_modern_tls13(out: Path):
    rng = _seeded("tls13")
    f = Flow(CLIENT, SERVER, 49158, 25, BASE_TS + 60)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=[CS["TLS13_AES_256_GCM_SHA384"], CS["TLS13_AES_128_GCM_SHA256"], CS["TLS13_CHACHA20_POLY1305"], CS["ECDHE_RSA_AES256_GCM_SHA384"]], selected=CS["TLS13_AES_256_GCM_SHA384"], sel_version=VER["TLS13"], chain=None, tls13=True)
    f.close()
    write_pcap(out, f.frames)


def scenario_incomplete(out: Path):
    """STARTTLS accepted, ClientHello seen, capture ends before any ServerHello."""
    rng = _seeded("incomplete")
    f = Flow(CLIENT, SERVER, 49159, 25, BASE_TS + 70)
    smtp_prelude(f)
    ch = client_hello(legacy_version=VER["TLS12"], ciphers=MODERN_OFFER, sni=MAIL, rng=rng)
    f.send("c", record(22, VER["TLS10"], ch))
    f.truncate_after_data(sum(1 for fr in f.frames if fr.is_data) - 1)
    write_pcap(out, f.frames)


def scenario_retransmit_reorder(out: Path):
    rng = _seeded("retx")
    f = Flow(CLIENT, SERVER, 49160, 25, BASE_TS + 80, mss=300)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=MODERN_OFFER, selected=CS["ECDHE_RSA_AES256_GCM_SHA384"], sel_version=VER["TLS12"], chain=good_chain(), split=300)
    n = sum(1 for fr in f.frames if fr.is_data)
    # duplicate (retransmit) one ClientHello segment and swap two server-flight segments
    f.duplicate_data_frame(n - 12 if n > 14 else 5)
    server_idxs = [i for i, fr in enumerate(f.frames) if fr.is_data and fr.direction == "s"]
    a, b = server_idxs[-6], server_idxs[-5]
    data_idx = [i for i, fr in enumerate(f.frames) if fr.is_data]
    f.swap_data_frames(data_idx.index(a), data_idx.index(b))
    f.close()
    write_pcap(out, f.frames)


def scenario_plaintext_auth(out: Path):
    f = Flow(CLIENT, SERVER, 49161, 25, BASE_TS + 90)
    f.send("s", f"220 {MAIL} ESMTP Postfix\r\n".encode())
    f.send("c", b"EHLO client.example.test\r\n")
    f.send("s", f"250-{MAIL}\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n".encode())
    f.send("c", b"AUTH PLAIN AAAAAAAA\r\n")  # placeholder token, never a real credential
    f.send("s", b"235 2.7.0 Authentication successful\r\n")
    f.send("c", b"MAIL FROM:<sender@example.test>\r\n")
    f.send("s", b"250 2.1.0 Ok\r\n")
    f.send("c", b"QUIT\r\n")
    f.send("s", b"221 2.0.0 Bye\r\n")
    f.close()
    write_pcap(out, f.frames)


def scenario_nonstandard_port(out: Path):
    rng = _seeded("port2525")
    f = Flow(CLIENT, SERVER, 49162, 2525, BASE_TS + 100)
    smtp_prelude(f)
    run_tls(f, rng, legacy_version=VER["TLS12"], offered=MODERN_OFFER, selected=CS["ECDHE_RSA_AES256_GCM_SHA384"], sel_version=VER["TLS12"], chain=good_chain())
    f.close()
    write_pcap(out, f.frames)


def scenario_starttls_rejected(out: Path):
    f = Flow(CLIENT, SERVER, 49163, 25, BASE_TS + 110)
    smtp_prelude(f, reject=True)
    f.send("c", b"QUIT\r\n")
    f.send("s", b"221 2.0.0 Bye\r\n")
    f.close()
    write_pcap(out, f.frames)


def scenario_corrupted(out: Path):
    out.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + os.urandom(0) + bytes(range(7, 200)) * 3)


def scenario_empty(out: Path):
    write_pcap(out, [])


def scenario_unsupported_linktype(out: Path):
    f = Flow(CLIENT, SERVER, 49164, 25, BASE_TS + 120)
    smtp_prelude(f)
    write_pcap(out, f.frames, linktype=147)


# name -> (builder, expectation manifest). ``rules`` must fire, ``absent`` must not.
SCENARIOS = {
    "smtp_starttls_tls12_complete.pcap": (
        scenario_smtp_tls12_complete,
        dict(title="SMTP STARTTLS, TLS 1.2, complete handshake", protocols=["smtp"], tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", rules=["SMS-STL-001", "SMS-TLS-014"], absent=["SMS-TLS-001", "SMS-CIP-001", "SMS-CIP-003", "SMS-TLS-013", "SMS-STL-004", "SMS-CRT-001", "SMS-CRT-006"], demo=True),
    ),
    "smtp_starttls_missing_handshake.pcap": (
        scenario_smtp_missing_handshake,
        dict(title="SMTP STARTTLS accepted, no TLS data captured", protocols=["smtp"], tls_version=None, cipher=None, rules=["SMS-TLS-013"], absent=["SMS-STL-001", "SMS-TLS-001", "SMS-CIP-001", "SMS-TLS-014"], demo=True),
    ),
    "imap_starttls.pcap": (
        scenario_imap,
        dict(title="IMAP STARTTLS, TLS 1.2", protocols=["imap"], tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", rules=["SMS-STL-001", "SMS-TLS-014"], absent=["SMS-TLS-001", "SMS-CIP-001"]),
    ),
    "pop3_stls.pcap": (
        scenario_pop3,
        dict(title="POP3 STLS, TLS 1.2", protocols=["pop3"], tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", rules=["SMS-STL-001", "SMS-TLS-014"], absent=["SMS-TLS-001", "SMS-CIP-001"]),
    ),
    "smtp_deprecated_tls10.pcap": (
        scenario_deprecated_tls10,
        dict(title="SMTP STARTTLS, deprecated TLS 1.0, 3DES, weak expired certificate", protocols=["smtp"], tls_version="TLSv1.0", cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA", rules=["SMS-TLS-001", "SMS-CIP-001", "SMS-CIP-002", "SMS-CIP-003", "SMS-CRT-001", "SMS-CRT-003", "SMS-CRT-004", "SMS-CRT-006"], absent=["SMS-TLS-014", "SMS-TLS-013"], demo=True),
    ),
    "smtp_legacy_cipher_tls12.pcap": (
        scenario_legacy_cipher_tls12,
        dict(title="SMTP STARTTLS, TLS 1.2 with RC4 selected", protocols=["smtp"], tls_version="TLSv1.2", cipher="TLS_RSA_WITH_RC4_128_SHA", rules=["SMS-CIP-001", "SMS-CIP-002", "SMS-CIP-003"], absent=["SMS-TLS-001", "SMS-TLS-014"]),
    ),
    "smtp_starttls_tls13.pcap": (
        scenario_modern_tls13,
        dict(title="SMTP STARTTLS, TLS 1.3 (certificate encrypted)", protocols=["smtp"], tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", rules=["SMS-STL-001", "SMS-TLS-014", "SMS-CRT-005"], absent=["SMS-TLS-001", "SMS-CIP-001", "SMS-CRT-001"], demo=True),
    ),
    "smtp_incomplete_clienthello_only.pcap": (
        scenario_incomplete,
        dict(title="SMTP STARTTLS, capture ends after ClientHello", protocols=["smtp"], tls_version=None, cipher=None, rules=["SMS-TLS-012", "SMS-TLS-013"], absent=["SMS-TLS-001", "SMS-CIP-001", "SMS-TLS-014"]),
    ),
    "smtp_retransmit_reorder.pcap": (
        scenario_retransmit_reorder,
        dict(title="SMTP STARTTLS with retransmitted and re-ordered segments", protocols=["smtp"], tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", rules=["SMS-STL-001", "SMS-TLS-014"], absent=["SMS-TLS-001", "SMS-CIP-001"]),
    ),
    "smtp_plaintext_auth.pcap": (
        scenario_plaintext_auth,
        dict(title="SMTP AUTH in cleartext although STARTTLS was advertised", protocols=["smtp"], tls_version=None, cipher=None, rules=["SMS-STL-004", "SMS-STL-003"], absent=["SMS-STL-001", "SMS-TLS-013"]),
    ),
    "smtp_nonstandard_port.pcap": (
        scenario_nonstandard_port,
        dict(title="SMTP STARTTLS on non-standard port 2525", protocols=["smtp"], tls_version="TLSv1.2", cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", rules=["SMS-STL-001", "SMS-TLS-014"], absent=["SMS-TLS-001"]),
    ),
    "smtp_starttls_rejected.pcap": (
        scenario_starttls_rejected,
        dict(title="SMTP STARTTLS rejected by server (454)", protocols=["smtp"], tls_version=None, cipher=None, rules=["SMS-STL-002"], absent=["SMS-STL-001", "SMS-TLS-013"]),
    ),
}

# Fixtures that must be REJECTED by ingestion (never analysed).
INVALID = {
    "corrupted.pcap": (scenario_corrupted, "corrupt"),
    "empty.pcap": (scenario_empty, "empty"),
    "unsupported_linktype.pcap": (scenario_unsupported_linktype, "unsupported_linktype"),
}


def build_all(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"valid": {}, "invalid": {}}
    for name, (fn, expect) in SCENARIOS.items():
        fn(out_dir / name)
        manifest["valid"][name] = expect
    for name, (fn, kind) in INVALID.items():
        fn(out_dir / name)
        manifest["invalid"][name] = kind
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures_out")
    m = build_all(target)
    print(f"wrote {len(m['valid'])} valid + {len(m['invalid'])} invalid captures to {target}")
