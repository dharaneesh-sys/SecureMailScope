"""Email-protocol identification from payload signatures *and* ports.

Port numbers are only a hint; a recognised banner/command wins. TShark's own
dissectors are used for the actual decoding once a stream's protocol is known.
"""

from __future__ import annotations

import re

WELL_KNOWN = {25: "smtp", 587: "smtp", 465: "smtp", 110: "pop3", 995: "pop3", 143: "imap", 993: "imap"}
IMPLICIT_TLS_PORTS = {465, 993, 995}
TSHARK_PROTO = {"smtp": "smtp", "imap": "imap", "pop3": "pop"}

_SMTP_BANNER = re.compile(rb"^220[ -][^\r\n]*\b(E?SMTP)\b", re.I)
_IMAP_BANNER = re.compile(rb"^\* (OK|PREAUTH|BYE)\b")
_POP_BANNER = re.compile(rb"^\+OK\b")
_SMTP_CMD = re.compile(rb"^(EHLO|HELO) ", re.I)
_IMAP_CMD = re.compile(rb"^[A-Za-z0-9.]{1,16} (CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|NOOP|LOGOUT|ID)\b", re.I)
_POP_CMD = re.compile(rb"^(CAPA|STLS|USER|APOP|QUIT)\b", re.I)
_TLS_RECORD = re.compile(rb"^\x16\x03[\x00-\x04]")


def detect_from_payload(payload: bytes, from_server_side: bool | None = None) -> str | None:
    """Return ``smtp|imap|pop3|tls`` or None."""
    if _TLS_RECORD.match(payload):
        return "tls"
    for rx, proto in ((_SMTP_BANNER, "smtp"), (_IMAP_BANNER, "imap"), (_POP_BANNER, "pop3")):
        if rx.match(payload):
            return proto
    for rx, proto in ((_SMTP_CMD, "smtp"), (_IMAP_CMD, "imap"), (_POP_CMD, "pop3")):
        if rx.match(payload):
            return proto
    return None


def hex_to_bytes(colon_hex: str) -> bytes:
    try:
        return bytes.fromhex(colon_hex.replace(":", ""))
    except ValueError:
        return b""


def decide_protocol(port_proto: str | None, sig_proto: str | None) -> tuple[str | None, str | None, str | None]:
    """Return (protocol, detected_by, note)."""
    if sig_proto in ("smtp", "imap", "pop3"):
        if port_proto == sig_proto:
            return sig_proto, "both", None
        if port_proto and port_proto != sig_proto:
            return sig_proto, "banner", f"payload signature indicates {sig_proto.upper()} although the port suggests {port_proto.upper()}"
        return sig_proto, "banner", None
    if port_proto:
        return port_proto, "port", None
    return None, None, None
