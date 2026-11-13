from app.rules.registry import all_rules


def rule_versions_map() -> dict[str, int]:
    return {r.meta.rule_id: r.meta.version for r in all_rules()}
