"""Privacy-preserving field trees for the packet-detail view."""

from __future__ import annotations

from typing import Any

DROP_SUBSTR = ("random", "session_id", "app_data", "ja3", "ja4", "_ws.expert", "key_share", "tls.handshake.sig_hash_alg_tree", "tcp.options", "tcp.segment", "tcp.analysis", "tcp.stream.", "tcp.checksum", "ip.checksum")
KEEP_FRAME = {"frame.number", "frame.len", "frame.time_epoch", "frame.time_utc", "frame.protocols"}
KEEP_IP = {"ip.src", "ip.dst", "ip.ttl", "ip.proto", "ip.len", "ipv6.src", "ipv6.dst"}
KEEP_TCP = {"tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq", "tcp.ack", "tcp.len", "tcp.flags", "tcp.window_size_value"}


def _clean(o: Any, depth: int = 0) -> Any:
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if any(s in k for s in DROP_SUBSTR):
                continue
            if k.endswith("tls.handshake.certificate") or k == "tls.handshake.certificate":
                vals = v if isinstance(v, list) else [v]
                out[k] = [f"<{len(str(x).split(':'))} bytes DER - parsed in Certificate Inspector>" for x in vals]
                continue
            out[k] = _clean(v, depth + 1)
        return out
    if isinstance(o, list):
        return [_clean(x, depth + 1) for x in o]
    if isinstance(o, str) and len(o) > 140:
        return o[:137] + "..."
    return o


def sanitize_layers(layers: dict, text_summary: str | None = None) -> dict:
    tree: dict[str, Any] = {}
    if "frame" in layers:
        tree["frame"] = {k: v for k, v in layers["frame"].items() if k in KEEP_FRAME}
    ip = layers.get("ip") or layers.get("ipv6")
    if ip:
        tree["ip"] = {k: v for k, v in ip.items() if k in KEEP_IP}
    if "tcp" in layers:
        tree["tcp"] = {k: v for k, v in layers["tcp"].items() if k in KEEP_TCP}
    if "tls" in layers:
        tree["tls"] = _clean(layers["tls"])
    for p in ("smtp", "imap", "pop"):
        if p in layers:
            tree[p] = {"note": "Application payload is not stored (credentials/message content protection).", "event": text_summary or "(see Protocol Explorer)"}
    return tree
