"""IMAP (RFC 3501 / STARTTLS RFC 2595, 9051) event extraction."""

from __future__ import annotations

import re

from .email_common import EmailAnalyzer, Line, short
from .frames import FrameMeta
from .models import EmailSessionObs, ProtoEvent
from .tshark_runner import as_list

_CAP_BRACKET = re.compile(r"\[CAPABILITY ([^\]]+)\]", re.I)


class ImapAnalyzer(EmailAnalyzer):
    protocol = "imap"

    def __init__(self) -> None:
        self._starttls_tag: str | None = None

    def lines(self, layers: dict, meta: FrameMeta) -> list[Line]:
        imap = layers.get("imap")
        if not isinstance(imap, dict):
            return []
        is_req = str(imap.get("imap.isrequest", "0")) == "1"
        out = []
        for raw in as_list(imap.get("imap.line")):
            if isinstance(raw, str) and raw.strip():
                out.append(Line("req" if is_req else "resp", raw.strip()))
        return out

    def handle(self, s: EmailSessionObs, line: Line, ev: ProtoEvent) -> ProtoEvent | None:
        if line.kind == "req":
            parts = line.text.split(None, 2)
            if len(parts) < 2:
                return None
            tag, verb = parts[0], parts[1].upper()
            ev.verb = verb
            if verb == "STARTTLS":
                ev.summary, ev.kind = "STARTTLS", "tls_transition"
                s.starttls_command = ev
                self._starttls_tag = tag
            elif verb in ("LOGIN", "AUTHENTICATE"):
                mech = parts[2].split()[0].upper() if verb == "AUTHENTICATE" and len(parts) > 2 else ""
                ev.summary = f"{verb} {mech} [credentials not stored]".replace("  ", " ").strip()
                s.auth_events.append(ev)
            elif verb in ("SELECT", "EXAMINE", "FETCH", "UID", "SEARCH", "APPEND", "LIST", "LSUB", "STATUS", "CREATE", "DELETE", "RENAME", "COPY", "EXPUNGE"):
                ev.summary = f"{verb} [parameters redacted]"
                s.plaintext_transaction.append(ev)
            else:
                ev.summary = verb
            return ev
        text = line.text
        ev.summary = short(text)
        if text.startswith("* OK") and s.banner is None and not s.events:
            ev.kind = "greeting"
            s.banner = short(_CAP_BRACKET.sub("", text[4:]).strip(), 80)
        m = _CAP_BRACKET.search(text) if text.startswith("* OK") else None
        caps_str = m.group(1) if m else (text[len("* CAPABILITY ") :] if text.upper().startswith("* CAPABILITY ") else None)
        if caps_str is not None:
            caps = caps_str.split()
            s.capabilities = caps
            s.starttls_offered = any(c.upper() == "STARTTLS" for c in caps)
            ev.kind = "capability"
            ev.summary = "CAPABILITY: " + ", ".join(caps[:10])
        parts = text.split(None, 2)
        if self._starttls_tag and parts and parts[0] == self._starttls_tag and s.starttls_response is None:
            ev.kind = "tls_transition"
            s.starttls_response = ev
            s.starttls_accepted = len(parts) > 1 and parts[1].upper() == "OK"
            ev.verb = parts[1].upper() if len(parts) > 1 else ""
        return ev
