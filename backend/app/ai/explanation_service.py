"""Built-in (deterministic) explanations plus the optional AI layer."""

from __future__ import annotations

import datetime as dt
from collections import Counter

from .prioritizer import build_prompt, parse_and_validate
from .provider import AiError, build_provider

AI_LABEL = "AI-generated explanation - not a verified parser fact. Verified facts are the findings and evidence listed beside it."


def group_findings(findings: list[dict]) -> list[dict]:
    """Collapse per-session findings to per-rule groups (what the AI/summary sees)."""
    groups: dict[str, dict] = {}
    for f in findings:
        g = groups.setdefault(f["rule_id"], {**f, "count": 0})
        g["count"] += 1
        g["risk_score"] = max(g["risk_score"], f["risk_score"])
    return sorted(groups.values(), key=lambda g: -g["risk_score"])


def builtin_summary(findings: list[dict], counters: dict, limitations: list[str]) -> dict:
    sev = Counter(f["severity"] for f in findings if f["observation_type"] not in ("secure_configuration", "insufficient_evidence") or f["severity"] != "info")
    issues = [f for f in findings if f["severity"] != "info"]
    gaps = [f for f in findings if f["observation_type"] == "insufficient_evidence"]
    positive = [f for f in findings if f["observation_type"] == "secure_configuration"]
    sessions = counters.get("email_sessions", 0)
    parts = [f"{counters.get('packets', 0)} packets were analysed; {sessions} email session(s) and {counters.get('tls_handshakes', 0)} parsed TLS handshake(s) were identified."]
    if issues:
        order = ["critical", "high", "medium", "low"]
        parts.append("Weaknesses/observations needing attention: " + ", ".join(f"{sev[s]} {s}" for s in order if sev.get(s)) + ".")
        top = group_findings(issues)[:3]
        parts.append("Highest-priority items: " + "; ".join(f"{g['title']} ({g['rule_id']}, score {g['risk_score']})" for g in top) + ".")
    else:
        parts.append("No weaknesses were positively observed in the available evidence.")
    if positive:
        parts.append(f"{len(positive)} modern/secure configuration observation(s) were recorded.")
    if gaps:
        parts.append(f"{len(gaps)} item(s) could not be assessed because the capture lacks the evidence; these are not confirmed weaknesses.")
    return {"source": "built-in (rule-based)", "text": " ".join(parts), "limitations": limitations}


def generate_ai_summary(cfg: dict, findings: list[dict], api_key: str | None = None) -> dict:
    base = {"label": AI_LABEL, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    try:
        provider = build_provider(cfg, api_key)
    except AiError as exc:
        return {**base, "status": "error", "error": str(exc)}
    if provider is None:
        return {**base, "status": "disabled", "message": "No AI provider configured. Built-in explanations are used."}
    grouped = group_findings(findings)
    try:
        raw = provider.complete(build_prompt(grouped))
        parsed = parse_and_validate(raw, {g["rule_id"] for g in grouped})
    except (AiError, ValueError) as exc:
        return {**base, "status": "error", "provider": provider.name, "model": provider.model, "error": str(exc)}
    return {**base, "status": "generated", "provider": provider.name, "model": provider.model, **parsed}
