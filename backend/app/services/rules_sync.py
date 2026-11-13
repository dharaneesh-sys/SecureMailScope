"""Keep the ``security_rules`` table in step with the code registry and version rule sets."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.tables import RuleVersion, SecurityRule
from app.rules.registry import all_rules
from app.rules.rule_config import ruleset_signature


def sync_rules(db: Session) -> None:
    existing = {r.rule_id: r for r in db.query(SecurityRule).all()}
    for rule in all_rules():
        m = rule.meta
        row = existing.get(m.rule_id)
        fields = dict(name=m.name, category=m.category, severity=m.severity, description=m.description, detection=m.detection,
                      evidence_requirements=m.evidence_requirements, remediation=m.remediation, references=list(m.references), version=m.version)
        if row is None:
            db.add(SecurityRule(rule_id=m.rule_id, enabled=True, **fields))
        else:
            for k, v in fields.items():
                setattr(row, k, v)
    db.commit()
    current_signature(db, note="initial rule set", create=True)


def enabled_map(db: Session) -> dict[str, bool]:
    return {r.rule_id: r.enabled for r in db.query(SecurityRule).all()}


def current_signature(db: Session, note: str | None = None, create: bool = False) -> str:
    rows = db.query(SecurityRule).all()
    enabled = {r.rule_id: r.enabled for r in rows}
    versions = {r.rule_id: r.version for r in rows}
    sig = ruleset_signature(enabled, versions)
    if create and not db.query(RuleVersion).filter_by(signature=sig).first():
        db.add(RuleVersion(signature=sig, enabled=enabled, versions=versions, note=note))
        db.commit()
    return sig
