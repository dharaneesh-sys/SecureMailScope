"""Rule configuration: which rules run, and a stable version identifier for it.

Editing a rule's enabled flag creates a new *rule-set version*. Each analysis
records the version it used, so later edits never silently change old results.
"""

from __future__ import annotations

import hashlib
import json


def ruleset_signature(enabled: dict[str, bool], rule_versions: dict[str, int]) -> str:
    payload = json.dumps({"enabled": dict(sorted(enabled.items())), "versions": dict(sorted(rule_versions.items()))}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:12]
