"""SecureMailScope Risk Score (SMRS) v1 - deterministic, explainable.

NOT a CVSS score and not an industry-standard rating. Formula::

    score = clamp( base(severity) x observation_factor x completeness_factor
                   + multi_session_bonus + credential_bonus , 0, 100 )

Every factor is stored with the finding so the number can be audited.
"""

from __future__ import annotations

from collections import Counter

from app.rules.base import FindingDraft

MODEL_VERSION = "SMRS-1"
BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
OBSERVATION = {"weakness_observed": 1.0, "weak_option_offered": 0.6, "protocol_feature": 0.5, "insufficient_evidence": 0.4, "secure_configuration": 0.2}
COMPLETENESS = {"complete": 1.0, "partial": 0.85, "incomplete": 0.6}
RECOMMENDED = {
    "critical": "Remediate immediately.",
    "high": "Remediate in the next maintenance window.",
    "medium": "Schedule remediation.",
    "low": "Address as part of routine hardening.",
    "info": "No remediation required; review for awareness.",
}


def score_findings(drafts: list[FindingDraft]) -> list[dict]:
    """Return one risk record per draft (same order)."""
    per_rule = Counter(d.rule_id for d in drafts)
    out = []
    for d in drafts:
        base = BASE[d.severity]
        obs = OBSERVATION[d.observation_type]
        comp = COMPLETENESS[d.completeness]
        n = per_rule[d.rule_id]
        bonus_sessions = min(10, 3 * (n - 1)) if d.severity != "info" else 0
        bonus_cred = 5 if d.rule_id == "SMS-STL-004" else 0
        raw = base * obs * comp + bonus_sessions + bonus_cred
        score = max(0, min(100, round(raw)))
        factors = [
            {"factor": "Base score for severity", "value": f"{d.severity} -> {base}", "effect": base},
            {"factor": "Observation type", "value": f"{d.observation_type} x{obs}", "effect": round(base * obs - base, 1)},
            {"factor": "Evidence completeness", "value": f"{d.completeness} x{comp}", "effect": round(base * obs * comp - base * obs, 1)},
        ]
        if bonus_sessions:
            factors.append({"factor": "Affected sessions", "value": f"{n} sessions trigger this rule", "effect": bonus_sessions})
        if bonus_cred:
            factors.append({"factor": "Possible credential exposure", "value": "authentication in cleartext", "effect": bonus_cred})
        out.append({
            "score": score, "model": MODEL_VERSION, "factors": factors,
            "explanation": f"{d.severity.capitalize()} {d.observation_type.replace('_', ' ')} with {d.completeness} evidence" + (f" across {n} sessions" if n > 1 else "") + f" scores {score}/100 under {MODEL_VERSION} (not CVSS).",
            "recommended_action": RECOMMENDED[d.severity],
        })
    return out
