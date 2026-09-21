"""JSON-safe views of each detector's evidence dataclasses. Written as
explicit per-type converters rather than one generic dataclass walker,
since several fields are sets/tuples that need real translation
(sorted lists, not just "whatever json.dumps happens to accept") and
each type's interesting fields differ enough that a generic walker
would just hide that instead of simplifying it.
"""
from __future__ import annotations

from detection.evasion_fingerprint import EvasionFlag
from detection.physical_logical_fusion import PhysicalLogicalMismatch
from detection.ssh_bruteforce import BruteForceFinding, PasswordSprayFinding
from detection.timing_correlation import CrossAccountBurst
from detection.token_fork import TokenForkFinding


def _finite(x: float) -> float | None:
    return None if x == float("inf") else round(x, 2)


def serialize_evidence(item) -> dict:
    if isinstance(item, CrossAccountBurst):
        return {
            "signal": "cross_account_timing",
            "start_ts": item.start_ts, "end_ts": item.end_ts,
            "size": item.size, "user_ids": sorted(item.user_ids),
            "z_score": _finite(item.z_score), "is_recurring": item.is_recurring,
            "risk_score": _finite(item.risk_score),
        }
    if isinstance(item, PhysicalLogicalMismatch):
        return {
            "signal": "physical_logical", "user_id": item.user_id,
            "badge_building": item.badge_building, "login_building": item.login_building,
            "gap_seconds": round(item.gap_seconds, 1), "risk_score": _finite(item.risk_score),
        }
    if isinstance(item, EvasionFlag):
        return {
            "signal": "evasion_fingerprint", "user_id": item.user_id,
            "measured_rtt_ms": round(item.measured_rtt_ms, 1),
            "claimed_geo_distance_km": round(item.claimed_geo_distance_km, 1),
            "rtt_ratio": _finite(item.rtt_ratio), "ttl": item.ttl,
            "risk_score": _finite(item.risk_score),
        }
    if isinstance(item, TokenForkFinding):
        return {
            "signal": "token_fork", "user_id": item.user_id,
            "parent_token_id": item.parent_token_id,
            "device_ip_pairs": sorted([ip, device] for ip, device in item.device_ip_pairs),
            "time_span_seconds": round(item.time_span_seconds, 1),
            "risk_score": _finite(item.risk_score),
        }
    if isinstance(item, BruteForceFinding):
        return {
            "signal": "ssh_brute_force", "target_host": item.target_host,
            "src_ip": item.src_ip, "attempt_count": item.attempt_count,
            "risk_score": _finite(item.risk_score),
        }
    if isinstance(item, PasswordSprayFinding):
        return {
            "signal": "ssh_password_spray", "target_host": item.target_host,
            "distinct_sources": item.distinct_sources,
            "usernames": sorted(item.usernames),
            "risk_score": _finite(item.risk_score),
        }
    raise TypeError(f"no serializer registered for evidence type {type(item)!r}")


def serialize_risk(score, id_field: str) -> dict:
    return {
        id_field: getattr(score, id_field),
        "total_score": _finite(score.total_score),
        "num_signals_tripped": score.num_signals_tripped,
        "signal_scores": {k: _finite(v) for k, v in score.signal_scores.items()},
        "evidence": {k: [serialize_evidence(item) for item in v] for k, v in score.evidence.items()},
    }
