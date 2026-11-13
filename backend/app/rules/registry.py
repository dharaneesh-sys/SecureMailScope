from __future__ import annotations

from .base import Rule

_REGISTRY: dict[str, Rule] = {}


def register(cls):
    inst = cls()
    if inst.meta.rule_id in _REGISTRY:
        raise RuntimeError(f"duplicate rule id {inst.meta.rule_id}")
    _REGISTRY[inst.meta.rule_id] = inst
    return cls


def all_rules() -> list[Rule]:
    # import for side effects (registration)
    from . import certificate_rules, cipher_rules, smtp_rules, tls_rules  # noqa: F401

    return sorted(_REGISTRY.values(), key=lambda r: r.meta.rule_id)


def get_rule(rule_id: str) -> Rule | None:
    all_rules()
    return _REGISTRY.get(rule_id)
