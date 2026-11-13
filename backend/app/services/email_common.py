"""Shared machinery for the SMTP / IMAP / POP3 analyzers.

Privacy rule: only verbs, status codes, capability tokens and non-secret
parameters (e.g. EHLO domain, AUTH mechanism name) are retained. Credentials,
AUTH payloads, mail addresses, message bodies and mailbox content are never
copied out of the dissection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .frames import FrameMeta
from .models import EmailSessionObs, ProtoEvent


@dataclass
class Line:
    kind: str  # req | resp
    text: str
    code: str | None = None
    params: list[str] = field(default_factory=list)


class EmailAnalyzer:
    protocol = ""

    def lines(self, layers: dict, meta: FrameMeta) -> list[Line]:  # pragma: no cover - abstract
        raise NotImplementedError

    def handle(self, s: EmailSessionObs, line: Line, ev: ProtoEvent) -> ProtoEvent | None:  # pragma: no cover
        """Update session state; return event to store (None to drop)."""
        raise NotImplementedError

    def accepted_frame(self, s: EmailSessionObs) -> int | None:
        return s.starttls_response.frame if s.starttls_response and s.starttls_accepted else None

    def process(self, s: EmailSessionObs, frames: list[tuple[FrameMeta, dict]]) -> None:
        seen: set[tuple[str, int | None, int]] = set()
        for meta, layers in frames:
            if "tls" in layers and self.accepted_frame(s) is not None:
                break
            acc = self.accepted_frame(s)
            if acc is not None and meta.number > acc:
                break  # everything after an accepted STARTTLS/STLS is TLS, not protocol text
            if meta.retransmission:
                continue
            direction = "client->server" if (meta.src, meta.sport) == (s.client_ip, s.client_port) else "server->client"
            key = (direction, meta.seq, meta.plen)
            if meta.plen and key in seen:
                continue
            seen.add(key)
            for line in self.lines(layers, meta):
                ev = ProtoEvent(meta.number, s.stream_id, meta.ts, direction, "command" if line.kind == "req" else "response", "", "")
                stored = self.handle(s, line, ev)
                if stored is not None:
                    s.events.append(stored)
        s.stream_completeness = "partial"


def short(text: str, n: int = 110) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"
