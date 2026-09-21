"""Signal 1: cross-account login-timing correlation.

Per-account anomaly detection can't see this pattern: many *unrelated*
accounts authenticating within a tight synchronized window is the
fingerprint of one actor cycling through a stolen-credential stash
(credential stuffing / a cracking farm), but every individual login in
that burst looks completely normal on its own. The signal only exists
at the population level.

Approach: for every event, look at the window of events starting at it
and ending WINDOW_SECONDS later; count distinct users in that window.
Windows with an unusually high distinct-user count (leave-one-out
z-score against the rest of the population, same convention as
iam-drift-sentinel's peer-group scoring) are merged into bursts. A
burst whose user set closely recurs on a separate occasion is scored
higher still - one coincidence is noise, the same set of accounts
bursting together repeatedly is automation.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

WINDOW_SECONDS = 3.0
MIN_BURST_SIZE = 4
RECURRENCE_JACCARD_THRESHOLD = 0.5


@dataclass
class CrossAccountBurst:
    burst_id: int
    start_ts: float
    end_ts: float
    user_ids: set[str]
    event_ids: set[str]
    z_score: float
    is_recurring: bool = False
    recurrence_matches: list[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.user_ids)

    @property
    def risk_score(self) -> float:
        return self.z_score * (2.0 if self.is_recurring else 1.0)


def _windowed_distinct_counts(sorted_events: list, window_seconds: float) -> list[tuple[int, int]]:
    """For each index i, distinct user count in [ts[i], ts[i]+window]. Returns (end_index, count) per i.

    Standard two-pointer sliding window: as i advances the window start
    only moves forward, so j is monotonically non-decreasing across the
    whole pass - O(n) total, not O(n) per i.
    """
    n = len(sorted_events)
    results = []
    j = 0
    counts: dict[str, int] = {}
    for i in range(n):
        if j < i:
            j = i
        while j < n and sorted_events[j]["timestamp"] - sorted_events[i]["timestamp"] <= window_seconds:
            uid = sorted_events[j]["user_id"]
            counts[uid] = counts.get(uid, 0) + 1
            j += 1
        results.append((j - 1, len(counts)))
        # slide window start forward by removing events[i] from counts
        uid_i = sorted_events[i]["user_id"]
        counts[uid_i] -= 1
        if counts[uid_i] == 0:
            del counts[uid_i]
    return results


def _as_dict(e) -> dict:
    """Normalize a sqlite3.Row (dict-subscriptable) or an AuthEvent
    dataclass (attribute-only) to a plain dict, so detection logic
    doesn't care which one it's given."""
    if isinstance(e, dict):
        return e
    try:
        return {"timestamp": e["timestamp"], "user_id": e["user_id"], "event_id": e["event_id"]}
    except (TypeError, IndexError, KeyError):
        return {"timestamp": e.timestamp, "user_id": e.user_id, "event_id": e.event_id}


def detect_bursts(
    auth_events,
    window_seconds: float = WINDOW_SECONDS,
    min_burst_size: int = MIN_BURST_SIZE,
) -> list[CrossAccountBurst]:
    events = sorted((_as_dict(e) for e in auth_events), key=lambda e: e["timestamp"])
    if len(events) < min_burst_size:
        return []

    window_counts = _windowed_distinct_counts(events, window_seconds)
    all_counts = [c for _, c in window_counts]

    hot_ranges = [(i, end) for i, (end, count) in enumerate(window_counts) if count >= min_burst_size]
    if not hot_ranges:
        return []

    # merge overlapping (start, end) index ranges into clusters
    merged: list[list[int, int]] = []
    for start, end in sorted(hot_ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    # Cold baseline: population stats from windows OUTSIDE every detected
    # burst, not just the current one. Excluding only the current cluster
    # (a naive leave-one-out) still lets a second recurring burst inflate
    # the first burst's baseline mean/stdev and damp its z-score - the
    # same class of self-contamination bug iam-drift-sentinel's peer
    # scoring hit, just showing up across bursts instead of across peers.
    hot_indices = set()
    for start, end in merged:
        hot_indices.update(range(start, end + 1))
    baseline = [c for idx, c in enumerate(all_counts) if idx not in hot_indices]
    baseline_mean = statistics.mean(baseline) if baseline else 0.0
    baseline_stdev = statistics.pstdev(baseline) if len(baseline) > 1 else 0.0

    bursts = []
    for burst_id, (start, end) in enumerate(merged):
        cluster_events = events[start:end + 1]
        user_ids = {e["user_id"] for e in cluster_events}
        event_ids = {e["event_id"] for e in cluster_events}

        mean, stdev = baseline_mean, baseline_stdev
        size = len(user_ids)
        if stdev == 0:
            # no variance in the rest of the population - any burst here is
            # unboundedly anomalous rather than a divide-by-zero no-op
            z = float("inf") if size > mean else 0.0
        else:
            z = (size - mean) / stdev

        bursts.append(CrossAccountBurst(
            burst_id=burst_id, start_ts=cluster_events[0]["timestamp"],
            end_ts=cluster_events[-1]["timestamp"], user_ids=user_ids,
            event_ids=event_ids, z_score=z,
        ))

    _annotate_recurrence(bursts)
    return sorted(bursts, key=lambda b: b.risk_score, reverse=True)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _annotate_recurrence(bursts: list[CrossAccountBurst]) -> None:
    for i, b1 in enumerate(bursts):
        for j, b2 in enumerate(bursts):
            if i == j:
                continue
            if _jaccard(b1.user_ids, b2.user_ids) >= RECURRENCE_JACCARD_THRESHOLD:
                b1.is_recurring = True
                b1.recurrence_matches.append(b2.burst_id)
