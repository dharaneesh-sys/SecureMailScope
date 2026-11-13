"""Helpers for reading TShark JSON frame layers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

from .tshark_runner import as_list


@dataclass
class FrameMeta:
    number: int
    ts: float
    stream: int | None
    src: str
    sport: int
    dst: str
    dport: int
    seq: int | None
    plen: int
    payload_hex: str
    retransmission: bool


def parse_ts(v) -> float:
    """TShark emits epoch seconds in field mode but ISO-8601 (ns precision) in JSON mode (>=4.6)."""
    if v in (None, ""):
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    import datetime as dt
    txt = str(v).replace("Z", "+00:00")
    if "." in txt:
        head, rest = txt.split(".", 1)
        frac = "".join(ch for ch in rest if ch.isdigit())[:6].ljust(6, "0")
        tz = rest[len(rest.rstrip("0123456789+-:")) :] if False else ("+00:00" if "+" not in rest and "-" not in rest else rest[max(rest.find("+"), rest.find("-")) :])
        txt = f"{head}.{frac}{tz}"
    try:
        d = dt.datetime.fromisoformat(txt)
    except ValueError:
        return 0.0
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.timestamp()


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def frame_meta(layers: dict) -> FrameMeta:
    fr = layers.get("frame", {})
    ip = layers.get("ip") or layers.get("ipv6") or {}
    tcp = layers.get("tcp", {})
    src = ip.get("ip.src") or ip.get("ipv6.src") or ""
    dst = ip.get("ip.dst") or ip.get("ipv6.dst") or ""
    payload = tcp.get("tcp.payload", "")
    if isinstance(payload, list):
        payload = payload[0] if payload else ""
    ana = tcp.get("tcp.analysis", {}) if isinstance(tcp.get("tcp.analysis"), dict) else {}
    retrans = any(k in ana for k in ("tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission"))
    stream = tcp.get("tcp.stream")
    return FrameMeta(
        number=_int(fr.get("frame.number")),
        ts=parse_ts(fr.get("frame.time_epoch")),
        stream=_int(stream, None) if stream not in (None, "") else None,
        src=src,
        sport=_int(tcp.get("tcp.srcport")),
        dst=dst,
        dport=_int(tcp.get("tcp.dstport")),
        seq=_int(tcp.get("tcp.seq"), None) if tcp.get("tcp.seq") not in (None, "") else None,
        plen=_int(tcp.get("tcp.len")),
        payload_hex=payload or "",
        retransmission=retrans,
    )


def walk(obj: Any) -> Iterator[tuple[str, Any]]:
    """Yield every (key, value) pair in a nested TShark JSON tree."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            if isinstance(v, (dict, list)):
                yield from walk(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from walk(x)


def find_all(obj: Any, key: str) -> list[str]:
    out: list[str] = []
    for k, v in walk(obj):
        if k == key:
            out.extend(str(x) for x in as_list(v) if not isinstance(x, (dict, list)))
    return out


def find_first(obj: Any, key: str) -> str | None:
    vals = find_all(obj, key)
    return vals[0] if vals else None


def hex_int(v: str | None) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v, 16) if str(v).lower().startswith("0x") else int(v)
    except ValueError:
        return None
