from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.tables import AuditLog


def audit(db: Session, action: str, subject: str | None = None, **detail) -> None:
    db.add(AuditLog(action=action, subject=subject, detail=detail))
    db.commit()
