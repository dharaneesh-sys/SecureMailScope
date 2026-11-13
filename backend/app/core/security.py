"""Small security helpers: filename sanitising, path containment, redaction."""

from __future__ import annotations

import re
from pathlib import Path

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    base = _SAFE.sub("_", base).strip("._") or "capture"
    return base[:120]


def ensure_within(base: Path, target: Path) -> Path:
    """Resolve ``target`` and require it to be inside ``base`` (path-traversal guard)."""
    base_r = base.resolve()
    target_r = target.resolve()
    if base_r != target_r and base_r not in target_r.parents:
        raise ValueError("path escapes the permitted directory")
    return target_r
