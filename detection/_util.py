"""Shared helper so detection modules don't care whether they're handed
sqlite3.Row objects (dict-subscriptable) or dataclass instances
(attribute-only) from ingestion/schema.py."""
from __future__ import annotations


def as_dict(e, fields: tuple[str, ...]) -> dict:
    if isinstance(e, dict):
        return e
    try:
        return {f: e[f] for f in fields}
    except (TypeError, IndexError, KeyError):
        return {f: getattr(e, f) for f in fields}
