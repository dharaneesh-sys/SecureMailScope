"""SMTP (RFC 5321 / STARTTLS RFC 3207) event extraction."""

from __future__ import annotations

from .email_common import EmailAnalyzer, Line, short
from .frames import FrameMeta
from .models import EmailSessionObs, ProtoEvent
from .tshark_runner import as_list

_TRANSACTION = {"MAIL", "RCPT", "DATA", "BDAT", "VRFY", "EXPN"}


class SmtpAnalyzer(EmailAnalyzer):
    protocol = "smtp"

    def lines(self, layers: dict, meta: FrameMeta) -> list[Line]:
        smtp = layers.get("smtp")
        if not isinstance(smtp, dict):
            return []
        out: list[Line] = []
        for raw in as_list(smtp.get("smtp.command_line")):
            if isinstance(raw, str) and raw.strip():
                out.append(Line("req", raw.strip()))
        if "smtp.response" in smtp or "smtp.response_tree" in smtp:
            tree = smtp.get("smtp.response_tree")
            trees = tree if isinstance(tree, list) else [tree] if isinstance(tree, dict) else []
            raws = [r for r in as_list(smtp.get("smtp.response")) if isinstance(r, str)]
            for i, t in enumerate(trees):
                code = t.get("smtp.response.code")
                params = [p for p in as_list(t.get("smtp.rsp.parameter")) if isinstance(p, str)]
                text = (raws[i].strip() if i < len(raws) else "") or " ".join(params)
                out.append(Line("resp", text, str(code) if code else None, params))
        return out

    def handle(self, s: EmailSessionObs, line: Line, ev: ProtoEvent) -> ProtoEvent | None:
        if line.kind == "req":
            parts = line.text.split(None, 1)
            verb = parts[0].upper() if parts else ""
            ev.verb = verb
            if verb in ("EHLO", "HELO"):
                ev.summary = f"{verb} {short(parts[1]) if len(parts) > 1 else ''}".strip()
            elif verb == "STARTTLS":
                ev.summary, ev.kind = "STARTTLS", "tls_transition"
                s.starttls_command = ev
            elif verb == "AUTH":
                mech = parts[1].split()[0].upper() if len(parts) > 1 else ""
                ev.summary = f"AUTH {mech} [credentials not stored]".strip()
                s.auth_events.append(ev)
            elif verb in _TRANSACTION:
                ev.summary = f"{verb} [parameters redacted]"
                s.plaintext_transaction.append(ev)
            else:
                ev.summary = verb or "[unparsed command]"
            return ev
        # response
        ev.verb = line.code or ""
        ev.summary = short(f"{line.code or ''} {' '.join(line.params) if line.params and len(line.params) < 3 else line.text}".strip())
        if line.code == "220" and s.banner is None and not s.events:
            s.banner = short(line.text.replace("220", "", 1).strip(), 80)
            ev.kind = "greeting"
        if line.code == "250" and len(line.params) > 1:
            caps = [p.strip() for p in line.params[1:] if p.strip()]
            s.capabilities = caps
            s.starttls_offered = any(c.upper().startswith("STARTTLS") for c in caps)
            ev.kind = "capability"
            ev.summary = "250 capabilities: " + ", ".join(c.split()[0] for c in caps[:10])
        if s.starttls_command and s.starttls_response is None and ev.frame >= s.starttls_command.frame and ev.direction == "server->client":
            s.starttls_response = ev
            ev.kind = "tls_transition"
            s.starttls_accepted = line.code == "220"
        return ev
