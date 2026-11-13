"""Rule framework: every rule is a pure function of parsed observations."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.models import AnalysisContext, EmailSessionObs, EvidenceRef, TlsSessionObs

SEVERITIES = ("critical", "high", "medium", "low", "info")
OBSERVATION_TYPES = (
    "weakness_observed",       # a weakness is positively present in observed data
    "weak_option_offered",    # weak option offered by one side, not (known to be) selected
    "secure_configuration",   # positively observed good configuration
    "protocol_feature",       # neutral protocol behaviour observed
    "insufficient_evidence",  # capture does not allow an assessment (NOT a vulnerability)
)


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    category: str
    severity: str
    description: str
    detection: str
    evidence_requirements: str
    remediation: str
    version: int = 1
    references: tuple[str, ...] = ()


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    severity: str
    category: str
    protocol: str | None
    stream_id: int | None
    description: str
    technical: str
    impact: str
    remediation: str
    observation_type: str
    completeness: str  # complete | partial | incomplete
    evidence: list[EvidenceRef] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


class Rule:
    meta: RuleMeta

    def evaluate(self, ctx: AnalysisContext) -> list[FindingDraft]:  # pragma: no cover - abstract
        raise NotImplementedError

    # helpers -------------------------------------------------------------
    def draft(self, *, title: str, stream: int | None, protocol: str | None, description: str, technical: str,
              impact: str, observation_type: str, completeness: str, evidence: list[EvidenceRef],
              severity: str | None = None, remediation: str | None = None, detail: dict | None = None) -> FindingDraft:
        m = self.meta
        return FindingDraft(
            rule_id=m.rule_id, title=title, severity=severity or m.severity, category=m.category,
            protocol=protocol, stream_id=stream, description=description, technical=technical, impact=impact,
            remediation=remediation or m.remediation, observation_type=observation_type, completeness=completeness,
            evidence=evidence, detail=detail or {},
        )


def tls_for(ctx: AnalysisContext, stream_id: int) -> TlsSessionObs | None:
    return next((t for t in ctx.tls_sessions if t.stream_id == stream_id), None)


def session_for(ctx: AnalysisContext, stream_id: int) -> EmailSessionObs | None:
    return next((s for s in ctx.sessions if s.stream_id == stream_id), None)


def ev_event(s: EmailSessionObs, e, description: str) -> EvidenceRef:
    return EvidenceRef(frame=e.frame, stream=s.stream_id, direction=e.direction, timestamp=e.ts, protocol=s.protocol.upper(),
                       description=description, fields={"event": e.summary}, parser="tshark:" + s.protocol, completeness="complete")


def ev_tls(t: TlsSessionObs, frame: int | None, ts: float | None, description: str, fields: dict, direction: str,
           completeness: str = "complete") -> EvidenceRef:
    return EvidenceRef(frame=frame, stream=t.stream_id, direction=direction, timestamp=ts, protocol="TLS",
                       description=description, fields=fields, parser="tshark:tls", completeness=completeness)
