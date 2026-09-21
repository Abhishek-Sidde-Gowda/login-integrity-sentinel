"""Fuses the five signal detectors into risk scores.

Four signals - cross-account timing, physical-logical fusion, evasion
fingerprinting, token forks - key naturally on a web-login `user_id`,
so they fuse into one IdentityRiskScore per user. The SSH signals key
on `target_host` plus attacker-controlled `src_ip`/`username` instead:
in this data model, SSH usernames are shared infrastructure accounts
(root, admin, deploy), not durable per-person identities the way
`user_id` is. Forcing them into the same identity score would be a
fabricated correlation, not a stronger one - so they fuse into a
separate HostRiskScore instead. A deployment where SSH usernames map
onto the same identity namespace as web logins could join the two;
this one is honest that its data doesn't.

An identity/host tripping multiple signals at once is a stronger
compromise signal than any single one alone - agreement is rewarded
multiplicatively, not just summed, mirroring iam-drift-sentinel's
fusion of permission drift + behavioral anomaly into one score.

Individual detectors' risk_score values are heuristic magnitudes on
different scales (a z-score, a ratio, a fixed weight, a raw count),
not calibrated probabilities - this fusion combines them pragmatically
rather than pretending otherwise. Each is clamped before aggregation
so an unbounded value (timing_correlation's z-score can legitimately
be +inf when its baseline has zero variance) can't make the total
score infinite and break sorting/display.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from detection.evasion_fingerprint import detect_evasion
from detection.physical_logical_fusion import detect_mismatches
from detection.ssh_bruteforce import detect_brute_force, detect_password_spray
from detection.timing_correlation import detect_bursts
from detection.token_fork import detect_forks

AGREEMENT_MULTIPLIER = 1.5  # per additional distinct signal tripped, applied multiplicatively
SIGNAL_SCORE_CAP = 500.0


def _clamp(score: float, cap: float = SIGNAL_SCORE_CAP) -> float:
    if score == float("inf"):
        return cap
    return max(0.0, min(score, cap))


@dataclass
class _FusedRisk:
    signal_scores: dict[str, float] = field(default_factory=dict)
    evidence: dict[str, list] = field(default_factory=lambda: defaultdict(list))

    @property
    def num_signals_tripped(self) -> int:
        return len(self.signal_scores)

    @property
    def total_score(self) -> float:
        if not self.signal_scores:
            return 0.0
        base = sum(self.signal_scores.values())
        return base * (AGREEMENT_MULTIPLIER ** (self.num_signals_tripped - 1))


@dataclass
class IdentityRiskScore(_FusedRisk):
    identity_id: str = ""


@dataclass
class HostRiskScore(_FusedRisk):
    host_id: str = ""


def _record(registry: dict, key: str, cls, id_field: str, signal_name: str, raw_score: float, evidence_item) -> None:
    if key not in registry:
        registry[key] = cls(**{id_field: key})
    r = registry[key]
    r.signal_scores[signal_name] = max(r.signal_scores.get(signal_name, 0.0), _clamp(raw_score))
    r.evidence[signal_name].append(evidence_item)


def compute_identity_risk(auth_events, badge_events, fingerprints, token_events) -> list[IdentityRiskScore]:
    scores: dict[str, IdentityRiskScore] = {}

    for burst in detect_bursts(auth_events):
        # a burst's risk applies to every member equally - each member
        # individually took part in (and is implicated by) the same
        # synchronized event, not a fraction of it
        for user_id in burst.user_ids:
            _record(scores, user_id, IdentityRiskScore, "identity_id",
                    "cross_account_timing", burst.risk_score, burst)

    for mismatch in detect_mismatches(auth_events, badge_events):
        _record(scores, mismatch.user_id, IdentityRiskScore, "identity_id",
                "physical_logical", mismatch.risk_score, mismatch)

    for flag in detect_evasion(auth_events, fingerprints):
        _record(scores, flag.user_id, IdentityRiskScore, "identity_id",
                "evasion_fingerprint", flag.risk_score, flag)

    for fork in detect_forks(token_events):
        _record(scores, fork.user_id, IdentityRiskScore, "identity_id",
                "token_fork", fork.risk_score, fork)

    return sorted(scores.values(), key=lambda r: r.total_score, reverse=True)


def compute_host_risk(ssh_events) -> list[HostRiskScore]:
    scores: dict[str, HostRiskScore] = {}

    for finding in detect_brute_force(ssh_events):
        _record(scores, finding.target_host, HostRiskScore, "host_id",
                "ssh_brute_force", finding.risk_score, finding)

    for finding in detect_password_spray(ssh_events):
        _record(scores, finding.target_host, HostRiskScore, "host_id",
                "ssh_password_spray", finding.risk_score, finding)

    return sorted(scores.values(), key=lambda r: r.total_score, reverse=True)
