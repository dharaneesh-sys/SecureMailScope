"""TCP stream table.

Actual payload reassembly (out-of-order, retransmission, overlap) is performed by
TShark's TCP dissector in the dissection pass. This module builds the per-stream
*metadata* from TShark's frame-level analysis fields and records whether the
capture looks complete, so downstream stages never assume a stream is whole just
because some payload was seen.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import StreamInfo
from .protocol_detection import WELL_KNOWN, decide_protocol, detect_from_payload, hex_to_bytes

FRAME_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.out_of_order", "tcp.analysis.lost_segment",
]
PAYLOAD_FIELDS = ["tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "tcp.payload"]


@dataclass
class FrameTable:
    total_frames: int
    tcp_frames: int
    non_tcp_frames: int
    first_ts: float | None
    last_ts: float | None
    streams: dict[int, StreamInfo]
    first_sender: dict[int, tuple[str, int]]
    stream_frames: dict[int, list[int]]


def _flags(value: str) -> int:
    try:
        return int(value, 16) if value.startswith("0x") else int(value or 0)
    except ValueError:
        return 0


def build_frame_table(rows) -> FrameTable:
    streams: dict[int, StreamInfo] = {}
    first_sender: dict[int, tuple[str, int]] = {}
    stream_frames: dict[int, list[int]] = {}
    total = tcp = 0
    first_ts = last_ts = None
    for r in rows:
        total += 1
        try:
            ts = float(r[1])
        except ValueError:
            ts = None
        if ts is not None:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        if r[7] == "":
            continue
        tcp += 1
        sid = int(r[7])
        src = r[3] or r[5]
        dst = r[4] or r[6]
        sport, dport = int(r[8] or 0), int(r[9] or 0)
        flags = _flags(r[10])
        plen = int(r[11] or 0)
        st = streams.get(sid)
        if st is None:
            # provisional orientation: SYN sender (or first sender) is the client
            st = StreamInfo(sid, src, sport, dst, dport, ts or 0.0, ts or 0.0)
            streams[sid] = st
            first_sender[sid] = (src, sport)
        if ts is not None:
            st.last_ts = max(st.last_ts, ts)
        st.frames += 1
        stream_frames.setdefault(sid, []).append(int(r[0]))
        if plen:
            st.payload_frames += 1
        if flags & 0x02 and not flags & 0x10:
            st.syn = True
            # SYN sender is the definitive client
            if (src, sport) != (st.client_ip, st.client_port):
                st.client_ip, st.client_port, st.server_ip, st.server_port = src, sport, dst, dport
            first_sender[sid] = (src, sport)
        if flags & 0x12 == 0x12:
            st.synack = True
        if flags & 0x01:
            st.fin = True
        if flags & 0x04:
            st.rst = True
        if r[12] or r[13]:
            st.retransmissions += 1
        if r[14]:
            st.out_of_order += 1
        if r[15]:
            st.lost_segments += 1
    return FrameTable(total, tcp, total - tcp, first_ts, last_ts, streams, first_sender, stream_frames)


def identify_streams(table: FrameTable, payload_rows) -> list[tuple[int, str]]:
    """Assign protocol + client/server orientation. Returns TShark decode-as entries."""
    first_payload: dict[int, dict[tuple[str, int], bytes]] = {}
    for r in payload_rows:
        if not r[0] or not r[4]:
            continue
        sid = int(r[0])
        src = r[1] or r[2]
        key = (src, int(r[3] or 0))
        first_payload.setdefault(sid, {}).setdefault(key, hex_to_bytes(r[4]))

    decode_as: list[tuple[int, str]] = []
    for sid, st in table.streams.items():
        fp = first_payload.get(sid, {})
        sig: str | None = None
        banner_side: tuple[str, int] | None = None
        client_side: tuple[str, int] | None = None
        tls_first = False
        for side, data in fp.items():
            d = detect_from_payload(data)
            if d == "tls":
                tls_first = True
                continue
            if d and sig is None:
                sig = d
            if d:
                is_banner = data[:4].startswith((b"220 ", b"220-", b"* OK", b"+OK", b"* PRE", b"* BYE"))
                if is_banner:
                    banner_side = side
                else:
                    client_side = side
        # orientation: banner sender is the server; command sender is the client
        if banner_side and banner_side != (st.server_ip, st.server_port):
            _swap(st)
        elif client_side and client_side != (st.client_ip, st.client_port):
            _swap(st)
        elif not banner_side and not client_side and not st.syn:
            if WELL_KNOWN.get(st.client_port) and not WELL_KNOWN.get(st.server_port):
                _swap(st)
        port_proto = WELL_KNOWN.get(st.server_port)
        proto, by, _ = decide_protocol(port_proto, sig)
        if proto is None and not tls_first:
            continue
        if proto is None:
            continue
        st.protocol, st.detected_by = proto, by
        port = st.server_port
        if tls_first:
            st.implicit_tls = True
        if tls_first and port in (465, 993, 995):
            continue  # TShark's default TLS ports cover these
        if port not in (25, 110, 143, 465, 993, 995) and not tls_first:
            tshark = {"smtp": "smtp", "imap": "imap", "pop3": "pop"}[proto]
            if (port, tshark) not in decode_as:
                decode_as.append((port, tshark))
    return decode_as


def _swap(st: StreamInfo) -> None:
    st.client_ip, st.server_ip = st.server_ip, st.client_ip
    st.client_port, st.server_port = st.server_port, st.client_port
