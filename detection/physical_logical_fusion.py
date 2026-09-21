"""Signal 2: physical-logical identity fusion.

Badge/RFID events are explicitly synthetic - see
ingestion/schema.py::BadgeEvent and the README's honesty note. This
fusion logic is written so real reader hardware could replace the
synthetic stream later without changing anything here; it only depends
on the BadgeEvent shape, not on how the events were produced.

Idea: physical presence can't be VPN-spoofed the way a source IP can.
If a badge read places a user in one building, and shortly after a
login originates from a network segment mapped to a DIFFERENT
building, that disagreement is a stronger corroborating signal than
any IP-only impossible-travel check - the attacker would need to have
physically bypassed the badge system too, not just proxied traffic.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass

from detection._util import as_dict
from ingestion.network_topology import building_for_ip

# A badge read older than this makes no claim about where the user
# currently is - people move between buildings, work from home after
# badging out, etc. Without a cutoff, a badge read from a week ago
# would "explain away" every subsequent login from anywhere.
MISMATCH_WINDOW_SECONDS = 4 * 3600

# The disagreement itself is binary evidence - a badge in one building
# and a login from another isn't "more true" the sooner it happens
# (unlike the other signals' continuous anomaly scores), so this is a
# fixed weight rather than a formula over gap_seconds.
MISMATCH_RISK_WEIGHT = 20.0

_AUTH_FIELDS = ("timestamp", "user_id", "event_id", "src_ip")
_BADGE_FIELDS = ("timestamp", "user_id", "event_id", "building")


@dataclass
class PhysicalLogicalMismatch:
    user_id: str
    auth_event_id: str
    badge_event_id: str
    badge_building: str
    login_building: str
    badge_ts: float
    login_ts: float

    @property
    def gap_seconds(self) -> float:
        return self.login_ts - self.badge_ts

    @property
    def risk_score(self) -> float:
        return MISMATCH_RISK_WEIGHT


def detect_mismatches(
    auth_events,
    badge_events,
    window_seconds: float = MISMATCH_WINDOW_SECONDS,
) -> list[PhysicalLogicalMismatch]:
    badge_by_user: dict[str, list[dict]] = defaultdict(list)
    for b in badge_events:
        badge_by_user[as_dict(b, _BADGE_FIELDS)["user_id"]].append(as_dict(b, _BADGE_FIELDS))
    for user_id, badges in badge_by_user.items():
        badges.sort(key=lambda x: x["timestamp"])

    mismatches = []
    for a in auth_events:
        ad = as_dict(a, _AUTH_FIELDS)
        login_building = building_for_ip(ad["src_ip"])
        if login_building is None:
            continue  # no known physical segment claimed - nothing to contradict

        user_badges = badge_by_user.get(ad["user_id"])
        if not user_badges:
            continue  # never badged in - no physical claim on record for this user

        timestamps = [b["timestamp"] for b in user_badges]
        idx = bisect.bisect_right(timestamps, ad["timestamp"]) - 1
        if idx < 0:
            continue  # login happens before this user's first known badge read

        last_badge = user_badges[idx]
        gap = ad["timestamp"] - last_badge["timestamp"]
        if gap > window_seconds:
            continue  # badge read too stale to make a current physical claim

        if last_badge["building"] != login_building:
            mismatches.append(PhysicalLogicalMismatch(
                user_id=ad["user_id"], auth_event_id=ad["event_id"],
                badge_event_id=last_badge["event_id"],
                badge_building=last_badge["building"], login_building=login_building,
                badge_ts=last_badge["timestamp"], login_ts=ad["timestamp"],
            ))

    return sorted(mismatches, key=lambda m: m.gap_seconds)
