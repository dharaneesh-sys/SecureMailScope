from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.tables import Finding, RuleVersion, SecurityRule
from app.schemas.api import RuleUpdate
from app.services import rules_sync
from app.services.audit import audit
from app.services.serializers import iso

router = APIRouter()


def _rule(r: SecurityRule, db: Session) -> dict:
    return {"rule_id": r.rule_id, "name": r.name, "category": r.category, "severity": r.severity, "description": r.description, "detection": r.detection,
            "evidence_requirements": r.evidence_requirements, "remediation": r.remediation, "references": r.references, "enabled": r.enabled, "version": r.version,
            "findings_total": db.query(Finding).filter(Finding.rule_id == r.rule_id).count()}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    rows = db.query(SecurityRule).order_by(SecurityRule.rule_id).all()
    versions = db.query(RuleVersion).order_by(RuleVersion.id.desc()).limit(25).all()
    return {"items": [_rule(r, db) for r in rows], "current_ruleset": rules_sync.current_signature(db),
            "history": [{"signature": v.signature, "created_at": iso(v.created_at), "note": v.note, "enabled_count": sum(1 for x in v.enabled.values() if x), "total": len(v.enabled)} for v in versions],
            "note": "Changing a rule creates a new rule-set version. Existing analyses keep the version they were run with; re-run them to apply the change."}


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    r = db.get(SecurityRule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    return _rule(r, db)


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, db: Session = Depends(get_db)):
    r = db.get(SecurityRule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    if r.enabled != body.enabled:
        r.enabled = body.enabled
        db.commit()
        sig = rules_sync.current_signature(db, note=f"{rule_id} {'enabled' if body.enabled else 'disabled'}", create=True)
        audit(db, "rule.updated", rule_id, enabled=body.enabled, ruleset=sig)
    return {**_rule(r, db), "current_ruleset": rules_sync.current_signature(db)}
