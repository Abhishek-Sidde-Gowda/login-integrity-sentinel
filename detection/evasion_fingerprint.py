"""Signal 3: evasion-aware network fingerprinting.

Impossible-travel rules that trust geoIP alone are beatable: a
residential-proxy relay can make a login claim to originate near the
victim's usual location while the traffic actually routes through a
faraway relay. Real network latency can't be faked the same way - if
the claimed distance is short, the round-trip time has a physical
floor it can't beat regardless of what the IP's geolocation database
says. See ingestion/schema.py::NetworkFingerprint for the RTT-floor
model and its documented limits (a rough sanity floor, not a precise
geolocation-from-latency estimator).

TTL is used as a weak corroborating signal, not a primary one: a
lower-than-expected TTL implies more router hops than a genuinely
local connection would need, which points the same direction as a high
RTT ratio without being definitive on its own (path asymmetry, load
balancers, and OS TTL defaults all add noise).
"""
from __future__ import annotations

from dataclasses import dataclass

from detection._util import as_dict

RTT_RATIO_THRESHOLD = 5.0
COMMON_INITIAL_TTLS = (64, 128, 255)
SUSPICIOUS_HOP_COUNT = 8

_FP_FIELDS = ("event_id", "measured_rtt_ms", "ttl", "ja3_hash",
              "claimed_geo_distance_km", "expected_rtt_ms_for_distance")
_AUTH_FIELDS = ("event_id", "user_id")


def _estimated_hop_count(ttl: int) -> int:
    initial = min((t for t in COMMON_INITIAL_TTLS if t >= ttl), default=COMMON_INITIAL_TTLS[-1])
    return initial - ttl


@dataclass
class EvasionFlag:
    event_id: str
    user_id: str
    measured_rtt_ms: float
    expected_rtt_ms_for_distance: float
    ttl: int
    ja3_hash: str
    claimed_geo_distance_km: float

    @property
    def rtt_ratio(self) -> float:
        if self.expected_rtt_ms_for_distance <= 0:
            return float("inf")
        return self.measured_rtt_ms / self.expected_rtt_ms_for_distance

    @property
    def risk_score(self) -> float:
        corroborated = _estimated_hop_count(self.ttl) > SUSPICIOUS_HOP_COUNT
        return self.rtt_ratio * (1.5 if corroborated else 1.0)


def detect_evasion(
    auth_events,
    fingerprints,
    rtt_ratio_threshold: float = RTT_RATIO_THRESHOLD,
) -> list[EvasionFlag]:
    auth_by_event = {as_dict(a, _AUTH_FIELDS)["event_id"]: as_dict(a, _AUTH_FIELDS) for a in auth_events}

    flags = []
    for fp in fingerprints:
        fd = as_dict(fp, _FP_FIELDS)
        if fd["expected_rtt_ms_for_distance"] <= 0:
            continue
        ratio = fd["measured_rtt_ms"] / fd["expected_rtt_ms_for_distance"]
        if ratio < rtt_ratio_threshold:
            continue

        auth = auth_by_event.get(fd["event_id"])
        flags.append(EvasionFlag(
            event_id=fd["event_id"], user_id=auth["user_id"] if auth else "unknown",
            measured_rtt_ms=fd["measured_rtt_ms"],
            expected_rtt_ms_for_distance=fd["expected_rtt_ms_for_distance"],
            ttl=fd["ttl"], ja3_hash=fd["ja3_hash"],
            claimed_geo_distance_km=fd["claimed_geo_distance_km"],
        ))

    return sorted(flags, key=lambda f: f.risk_score, reverse=True)
