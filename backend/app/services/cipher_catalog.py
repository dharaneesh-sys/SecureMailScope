"""IANA TLS cipher-suite catalogue and deterministic classification.

Only suites we actually know are classified. Unknown IDs are reported as
``UNKNOWN_0xXXXX`` and are *never* flagged as weak (no guessing).
"""

from __future__ import annotations

from dataclasses import dataclass

_RAW = """
0000 TLS_NULL_WITH_NULL_NULL
0001 TLS_RSA_WITH_NULL_MD5
0002 TLS_RSA_WITH_NULL_SHA
0003 TLS_RSA_EXPORT_WITH_RC4_40_MD5
0004 TLS_RSA_WITH_RC4_128_MD5
0005 TLS_RSA_WITH_RC4_128_SHA
0006 TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
0008 TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
0009 TLS_RSA_WITH_DES_CBC_SHA
000A TLS_RSA_WITH_3DES_EDE_CBC_SHA
0011 TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
0012 TLS_DHE_DSS_WITH_DES_CBC_SHA
0013 TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
0014 TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
0015 TLS_DHE_RSA_WITH_DES_CBC_SHA
0016 TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
0017 TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
0018 TLS_DH_anon_WITH_RC4_128_MD5
001A TLS_DH_anon_WITH_DES_CBC_SHA
001B TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
002F TLS_RSA_WITH_AES_128_CBC_SHA
0032 TLS_DHE_DSS_WITH_AES_128_CBC_SHA
0033 TLS_DHE_RSA_WITH_AES_128_CBC_SHA
0034 TLS_DH_anon_WITH_AES_128_CBC_SHA
0035 TLS_RSA_WITH_AES_256_CBC_SHA
0038 TLS_DHE_DSS_WITH_AES_256_CBC_SHA
0039 TLS_DHE_RSA_WITH_AES_256_CBC_SHA
003A TLS_DH_anon_WITH_AES_256_CBC_SHA
003B TLS_RSA_WITH_NULL_SHA256
003C TLS_RSA_WITH_AES_128_CBC_SHA256
003D TLS_RSA_WITH_AES_256_CBC_SHA256
0041 TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
0067 TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
006B TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
0084 TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
0096 TLS_RSA_WITH_SEED_CBC_SHA
009C TLS_RSA_WITH_AES_128_GCM_SHA256
009D TLS_RSA_WITH_AES_256_GCM_SHA384
009E TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
009F TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
00FF TLS_EMPTY_RENEGOTIATION_INFO_SCSV
1301 TLS_AES_128_GCM_SHA256
1302 TLS_AES_256_GCM_SHA384
1303 TLS_CHACHA20_POLY1305_SHA256
1304 TLS_AES_128_CCM_SHA256
1305 TLS_AES_128_CCM_8_SHA256
5600 TLS_FALLBACK_SCSV
C002 TLS_ECDH_ECDSA_WITH_RC4_128_SHA
C007 TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
C008 TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
C009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
C00A TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
C011 TLS_ECDHE_RSA_WITH_RC4_128_SHA
C012 TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
C013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
C014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
C023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
C024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
C027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
C028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
C02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
C02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
C02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
C030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
CCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
CCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
CCAA TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
"""

CIPHERS: dict[int, str] = {int(line.split()[0], 16): line.split()[1] for line in _RAW.strip().splitlines()}

TLS13_SUITES = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
SIGNALLING = {0x00FF, 0x5600}  # SCSVs: not real cipher suites

TLS_VERSIONS = {
    0x0200: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}
DEPRECATED_VERSIONS = {0x0200, 0x0300, 0x0301, 0x0302}


def version_name(v: int | None) -> str | None:
    if v is None:
        return None
    return TLS_VERSIONS.get(v, f"UNKNOWN_0x{v:04x}")


def cipher_name(cid: int) -> str:
    return CIPHERS.get(cid, f"UNKNOWN_0x{cid:04X}")


@dataclass(frozen=True)
class CipherInfo:
    id: int
    name: str
    known: bool
    weak_class: str | None  # null | export | anon | rc4 | des | 3des | md5 | None
    forward_secret: bool | None  # None when not determinable
    aead: bool | None
    signalling: bool = False

    @property
    def is_weak(self) -> bool:
        return self.weak_class is not None


def classify(cid: int) -> CipherInfo:
    name = cipher_name(cid)
    if cid in SIGNALLING:
        return CipherInfo(cid, name, True, None, None, None, True)
    if cid not in CIPHERS:
        return CipherInfo(cid, name, False, None, None, None)
    if cid in TLS13_SUITES:
        return CipherInfo(cid, name, True, None, True, True)
    n = name
    weak = None
    if "_NULL_" in n:
        weak = "null"
    elif "EXPORT" in n:
        weak = "export"
    elif "_anon_" in n:
        weak = "anon"
    elif "RC4" in n or "RC2" in n:
        weak = "rc4"
    elif "3DES" in n:
        weak = "3des"
    elif "_DES_" in n or "DES40" in n:
        weak = "des"
    elif n.endswith("_MD5"):
        weak = "md5"
    kex = n.split("_WITH_")[0] if "_WITH_" in n else ""
    fs = None
    if kex:
        if "ECDHE" in kex or "DHE" in kex:
            fs = True
        elif kex in ("TLS_RSA", "TLS_ECDH_ECDSA", "TLS_ECDH_RSA", "TLS_DH_RSA", "TLS_DH_DSS"):
            fs = False
    aead = any(x in n for x in ("_GCM_", "_CCM", "CHACHA20_POLY1305"))
    return CipherInfo(cid, name, True, weak, fs, aead)


WEAK_SEVERITY = {"null": "critical", "export": "critical", "anon": "critical", "rc4": "high", "des": "high", "md5": "high", "3des": "medium"}
WEAK_EXPLANATION = {
    "null": "NULL cipher suites provide no encryption at all.",
    "export": "EXPORT-grade suites use deliberately weakened (<=56-bit) keys and are breakable (FREAK/Logjam class).",
    "anon": "Anonymous key exchange performs no authentication and is trivially man-in-the-middle-able.",
    "rc4": "RC4 has practical keystream biases and is prohibited by RFC 7465.",
    "des": "Single DES has a 56-bit key and can be brute-forced.",
    "md5": "MD5-based MAC/PRF constructions are cryptographically broken.",
    "3des": "3DES has a 64-bit block size and is vulnerable to birthday attacks (SWEET32, CVE-2016-2183); deprecated by NIST.",
}
