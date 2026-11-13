"""Key/value application settings persisted in SQLite with typed defaults."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import settings as env
from app.models.tables import AppSetting

DEFAULTS: dict = {
    "local_only_mode": True,                  # never call external services (AI endpoints must be loopback)
    "retention_days": env.retention_days,
    "retain_original_captures": env.retain_original_captures,
    "max_upload_mb": env.max_upload_mb,
    "cert_reference": "capture",             # capture | analysis
    "ai_provider": env.ai_provider,          # none | ollama | openai_compatible
    "ai_endpoint": env.ai_endpoint,
    "ai_model": env.ai_model,
    "report_organisation": "ALPHA HUSTLERS - KGiSL Institute of Technology",
    "report_include_hex": False,
    "analyst_name": "Local analyst",
}
VALIDATORS = {
    "local_only_mode": bool, "retention_days": int, "retain_original_captures": bool, "max_upload_mb": int, "cert_reference": str,
    "ai_provider": str, "ai_endpoint": str, "ai_model": str, "report_organisation": str, "report_include_hex": bool, "analyst_name": str,
}


def get_all(db: Session) -> dict:
    stored = {r.key: r.value.get("v") for r in db.query(AppSetting).all()}
    return {k: stored.get(k, v) for k, v in DEFAULTS.items()}


def get(db: Session, key: str):
    row = db.get(AppSetting, key)
    return row.value.get("v") if row else DEFAULTS[key]


def update(db: Session, patch: dict) -> dict:
    errors = []
    for k, v in patch.items():
        if k not in DEFAULTS:
            errors.append(f"unknown setting '{k}'")
            continue
        typ = VALIDATORS[k]
        if typ is bool and not isinstance(v, bool):
            errors.append(f"'{k}' must be true/false")
        elif typ is int and (not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 100000):
            errors.append(f"'{k}' must be a non-negative integer")
        elif typ is str and (not isinstance(v, str) or len(v) > 300):
            errors.append(f"'{k}' must be a string (max 300 chars)")
    if "cert_reference" in patch and patch["cert_reference"] not in ("capture", "analysis"):
        errors.append("cert_reference must be 'capture' or 'analysis'")
    if "ai_provider" in patch and patch["ai_provider"] not in ("none", "ollama", "openai_compatible"):
        errors.append("ai_provider must be none, ollama or openai_compatible")
    if "max_upload_mb" in patch and isinstance(patch["max_upload_mb"], int) and not 1 <= patch["max_upload_mb"] <= 500:
        errors.append("max_upload_mb must be between 1 and 500")
    if errors:
        raise ValueError("; ".join(errors))
    for k, v in patch.items():
        row = db.get(AppSetting, k)
        if row:
            row.value = {"v": v}
        else:
            db.add(AppSetting(key=k, value={"v": v}))
    db.commit()
    return get_all(db)
