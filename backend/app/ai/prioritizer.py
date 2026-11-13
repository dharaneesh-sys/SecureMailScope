"""Build the (privacy-minimal) prompt and validate the model's answer against known findings."""

from __future__ import annotations

import json

SYSTEM = (
    "You are assisting a security analyst. You are given ESTABLISHED findings from a deterministic parser. "
    "Do not add, change or invent any protocol versions, cipher suites, certificates, packet facts or findings. "
    "Only explain and prioritise the findings provided. Respond with JSON: "
    '{"executive_summary": "<=120 words", "priorities": [{"rule_id": "...", "rationale": "<=40 words"}]}'
)


def build_payload(findings: list[dict]) -> list[dict]:
    keys = ("rule_id", "title", "severity", "category", "protocol", "observation_type", "completeness", "risk_score", "count")
    return [{k: f[k] for k in keys if k in f} for f in findings]


def build_prompt(findings: list[dict]) -> str:
    return SYSTEM + "\n\nFINDINGS:\n" + json.dumps(build_payload(findings), indent=1)


def parse_and_validate(raw: str, known_rule_ids: set[str]) -> dict:
    """Return only content that stays inside the established facts."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model did not return valid JSON: {exc}") from exc
    summary = str(data.get("executive_summary", ""))[:1200]
    prios = []
    for p in data.get("priorities", []) if isinstance(data.get("priorities"), list) else []:
        rid = str(p.get("rule_id", ""))
        if rid in known_rule_ids:  # discard any rule the parser did not produce
            prios.append({"rule_id": rid, "rationale": str(p.get("rationale", ""))[:400]})
    dropped = [str(p.get("rule_id")) for p in data.get("priorities", []) if isinstance(p, dict) and str(p.get("rule_id")) not in known_rule_ids]
    return {"executive_summary": summary, "priorities": prios, "discarded_unknown_rule_ids": dropped}
