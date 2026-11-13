"""PCAP / PCAPNG ingestion: content-based validation, hashing and metadata."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

# link-layer types the decoder pipeline is verified against
SUPPORTED_LINKTYPES = {0: "BSD loopback", 1: "Ethernet", 101: "Raw IP", 113: "Linux cooked (SLL)", 276: "Linux cooked v2 (SLL2)"}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "us"),
    b"\xa1\xb2\xc3\xd4": (">", "us"),
    b"\x4d\x3c\xb2\xa1": ("<", "ns"),
    b"\xa1\xb2\x3c\x4d": (">", "ns"),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_RECORD = 262144 * 4


class CaptureRejected(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class CaptureMeta:
    format: str
    linktype: int | None
    linktype_name: str | None
    packet_count: int
    first_ts: float | None = None
    last_ts: float | None = None
    truncated_tail: bool = False
    warnings: list[str] = field(default_factory=list)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_format(head: bytes) -> str:
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if head[:4] == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureRejected("unrecognised_format", "File content is not a PCAP or PCAPNG capture (magic number mismatch).")


def _scan_pcap(path: Path, size: int) -> CaptureMeta:
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise CaptureRejected("corrupt", "PCAP global header is truncated.")
        endian, res = PCAP_MAGICS[head[:4]]
        _, vmaj, vmin, _, _, snaplen, link = struct.unpack(endian + "IHHiIII", head)
        if vmaj != 2 or vmin not in (4,):
            raise CaptureRejected("corrupt", f"Unsupported or corrupt PCAP version {vmaj}.{vmin}.")
        if link not in SUPPORTED_LINKTYPES:
            raise CaptureRejected("unsupported_linktype", f"Link-layer type {link} is not supported (supported: {', '.join(f'{k}={v}' for k, v in SUPPORTED_LINKTYPES.items())}).")
        meta = CaptureMeta("pcap", link, SUPPORTED_LINKTYPES[link], 0)
        pos = 24
        limit = max(snaplen, 65535) if 0 < snaplen < MAX_RECORD else MAX_RECORD
        while pos < size:
            rec = fh.read(16)
            if len(rec) < 16:
                meta.truncated_tail = True
                meta.warnings.append("Capture ends with a truncated packet record header.")
                break
            sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
            if incl > limit:
                raise CaptureRejected("corrupt", f"Packet record {meta.packet_count + 1} has an implausible captured length ({incl}); the file appears corrupted.")
            ts = sec + frac / (1e9 if res == "ns" else 1e6)
            meta.first_ts = ts if meta.first_ts is None else meta.first_ts
            meta.last_ts = ts
            pos += 16 + incl
            if pos > size:
                meta.truncated_tail = True
                meta.warnings.append("Final packet record is truncated (capture was cut short).")
                break
            fh.seek(pos)
            meta.packet_count += 1
        return meta


def _scan_pcapng(path: Path, size: int) -> CaptureMeta:
    with open(path, "rb") as fh:
        blk = fh.read(12)
        if len(blk) < 12:
            raise CaptureRejected("corrupt", "PCAPNG section header is truncated.")
        btype, blen = struct.unpack("<II", blk[:8])
        bom = blk[8:12]
        endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
        if endian is None:
            raise CaptureRejected("corrupt", "PCAPNG byte-order magic is invalid.")
        meta = CaptureMeta("pcapng", None, None, 0)
        fh.seek(0)
        pos = 0
        links: list[int] = []
        while pos + 12 <= size:
            fh.seek(pos)
            h = fh.read(8)
            if len(h) < 8:
                break
            t, l = struct.unpack(endian + "II", h)
            if l < 12 or l % 4 or pos + l > size:
                if pos + l > size and l >= 12:
                    meta.truncated_tail = True
                    meta.warnings.append("Final PCAPNG block is truncated.")
                    break
                raise CaptureRejected("corrupt", f"PCAPNG block at offset {pos} has an invalid length ({l}).")
            if t == 1:  # Interface Description Block
                body = fh.read(4)
                if len(body) == 4:
                    links.append(struct.unpack(endian + "HH", body)[0])
            elif t in (6, 3):  # Enhanced / Simple packet block
                meta.packet_count += 1
            pos += l
        if links:
            bad = [x for x in links if x not in SUPPORTED_LINKTYPES]
            if bad and len(bad) == len(links):
                raise CaptureRejected("unsupported_linktype", f"Link-layer type {bad[0]} is not supported.")
            meta.linktype = links[0]
            meta.linktype_name = SUPPORTED_LINKTYPES.get(links[0])
        return meta


def validate_capture(path: Path) -> CaptureMeta:
    """Validate by *content*. Raises :class:`CaptureRejected` for unusable files."""
    size = path.stat().st_size
    if size == 0:
        raise CaptureRejected("empty", "The file is empty.")
    with open(path, "rb") as fh:
        head = fh.read(24)
    if len(head) < 24 and head[:4] in (*PCAP_MAGICS, PCAPNG_MAGIC):
        raise CaptureRejected("corrupt", "Capture header is truncated.")
    fmt = detect_format(head)
    meta = _scan_pcap(path, size) if fmt == "pcap" else _scan_pcapng(path, size)
    if meta.packet_count == 0:
        raise CaptureRejected("empty", "The capture is valid but contains no packets.")
    return meta
