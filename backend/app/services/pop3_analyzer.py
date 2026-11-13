"""POP3 (RFC 1939 / STLS RFC 2595) event extraction."""

from __future__ import annotations

from .email_common import EmailAnalyzer, Line, short
from .frames import FrameMeta
from .models import EmailSessionObs, ProtoEvent
from .protocol_detection import hex_to_bytes


def _capa_tokens(payload_hex: str) -> list[str]:
    """Return only the *capability keywords* from a CAPA multi-line response."""
    text = hex_to_bytes(payload_hex).decode("latin-1", "replace")
    toks: list[str] = []
    for ln in text.splitlines()[1:]:
        ln = ln.strip()
        if ln == ".":
            break
        if ln:
            toks.append(ln.split()[0].upper())
    return toks


class Pop3Analyzer(EmailAnalyzer):
    protocol = "pop3"

    def __init__(self) -> None:
        self._last_cmd: str | None = None

    def lines(self, layers: dict, meta: FrameMeta) -> list[Line]:
        pop = layers.get("pop")
        if not isinstance(pop, dict):
            return []
        out: list[Line] = []
        req = pop.get("pop.request_tree")
        if isinstance(req, dict):
            cmd = req.get("pop.request.command", "")
            param = req.get("pop.request.parameter", "")
            out.append(Line("req", f"{cmd} {param}".strip()))
        resp = pop.get("pop.response_tree")
        if isinstance(resp, dict):
            ind = resp.get("pop.response.indicator", "")
            desc = resp.get("pop.response.description", "")
            ln = Line("resp", f"{ind} {desc}".strip(), ind, [])
            ln.params = _capa_tokens(meta.payload_hex) if self._last_cmd == "CAPA" and ind == "+OK" else []
            out.append(ln)
        return out

    def handle(self, s: EmailSessionObs, line: Line, ev: ProtoEvent) -> ProtoEvent | None:
        if line.kind == "req":
            parts = line.text.split(None, 1)
            verb = parts[0].upper() if parts else ""
            self._last_cmd = verb
            ev.verb = verb
            if verb == "STLS":
                ev.summary, ev.kind = "STLS", "tls_transition"
                s.starttls_command = ev
            elif verb in ("USER", "PASS", "APOP"):
                ev.summary = f"{verb} [credentials not stored]"
                s.auth_events.append(ev)
            elif verb == "AUTH":
                mech = parts[1].split()[0].upper() if len(parts) > 1 else ""
                ev.summary = f"AUTH {mech} [credentials not stored]".strip()
                s.auth_events.append(ev)
            elif verb in ("RETR", "LIST", "STAT", "TOP", "DELE", "UIDL"):
                ev.summary = f"{verb} [parameters redacted]"
                s.plaintext_transaction.append(ev)
            else:
                ev.summary = verb
            return ev
        ev.verb = line.code or ""
        ev.summary = short(line.text)
        if s.banner is None and not s.events and line.code == "+OK":
            s.banner = short(line.text.replace("+OK", "", 1).strip(), 80)
            ev.kind = "greeting"
        if self._last_cmd == "CAPA" and line.params:
            s.capabilities = line.params
            s.starttls_offered = "STLS" in line.params
            ev.kind = "capability"
            ev.summary = "CAPA: " + ", ".join(line.params[:10])
        if self._last_cmd == "STLS" and s.starttls_command and s.starttls_response is None and ev.direction == "server->client":
            s.starttls_response = ev
            ev.kind = "tls_transition"
            s.starttls_accepted = line.code == "+OK"
        self._last_cmd = None
        return ev
