"""Signal 5: SSH brute force + low-and-slow password-spray detection.

Two distinct patterns, deliberately handled by different logic because
a single per-entity threshold can only ever catch one of them:

- Classic brute force: one source IP hammers one account with many
  failed attempts in a tight window. A per-(host, src_ip) failure-count
  threshold catches this easily.
- Low-and-slow password spray: many distinct source IPs, each trying a
  handful of common usernames a few times over hours - no single IP or
  account ever crosses a naive per-entity threshold. What stands out
  instead is the population-level pattern: an unusual fan-out of
  distinct source IPs failing against the SAME target host in the same
  window. This is the case a per-account or per-IP rule structurally
  cannot see, by construction.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from detection._util import as_dict

BRUTE_FORCE_WINDOW_SECONDS = 300.0
BRUTE_FORCE_THRESHOLD = 10

SPRAY_WINDOW_SECONDS = 5 * 3600.0
SPRAY_MIN_DISTINCT_SOURCES = 8

_SSH_FIELDS = ("event_id", "timestamp", "src_ip", "target_host", "username", "success")


@dataclass
class BruteForceFinding:
    target_host: str
    src_ip: str
    attempt_count: int
    window_start: float
    window_end: float

    @property
    def risk_score(self) -> float:
        return self.attempt_count


@dataclass
class PasswordSprayFinding:
    target_host: str
    window_start: float
    window_end: float
    src_ips: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)

    @property
    def distinct_sources(self) -> int:
        return len(self.src_ips)

    @property
    def risk_score(self) -> float:
        hours = max((self.window_end - self.window_start) / 3600.0, 0.1)
        return self.distinct_sources * len(self.usernames) / hours


def _max_window_count(sorted_ts: list[float], window_seconds: float) -> tuple[int, tuple[float, float] | None]:
    """Two-pointer sliding window: largest count of timestamps within
    any window_seconds-wide span, and that span's bounds."""
    n = len(sorted_ts)
    j = 0
    best_count, best_range = 0, None
    for i in range(n):
        if j < i:
            j = i
        while j < n and sorted_ts[j] - sorted_ts[i] <= window_seconds:
            j += 1
        count = j - i
        if count > best_count:
            best_count = count
            best_range = (sorted_ts[i], sorted_ts[j - 1])
    return best_count, best_range


def detect_brute_force(
    ssh_events,
    window_seconds: float = BRUTE_FORCE_WINDOW_SECONDS,
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> list[BruteForceFinding]:
    by_host_ip: dict[tuple[str, str], list[float]] = defaultdict(list)
    for e in ssh_events:
        ed = as_dict(e, _SSH_FIELDS)
        if ed["success"]:
            continue
        by_host_ip[(ed["target_host"], ed["src_ip"])].append(ed["timestamp"])

    findings = []
    for (host, src_ip), timestamps in by_host_ip.items():
        timestamps.sort()
        count, window = _max_window_count(timestamps, window_seconds)
        if count >= threshold:
            findings.append(BruteForceFinding(
                target_host=host, src_ip=src_ip, attempt_count=count,
                window_start=window[0], window_end=window[1],
            ))

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def detect_password_spray(
    ssh_events,
    window_seconds: float = SPRAY_WINDOW_SECONDS,
    min_distinct_sources: int = SPRAY_MIN_DISTINCT_SOURCES,
    brute_force_threshold: int = BRUTE_FORCE_THRESHOLD,
) -> list[PasswordSprayFinding]:
    by_host: dict[str, list[dict]] = defaultdict(list)
    for e in ssh_events:
        ed = as_dict(e, _SSH_FIELDS)
        if not ed["success"]:
            by_host[ed["target_host"]].append(ed)

    findings = []
    for host, events in by_host.items():
        events.sort(key=lambda e: e["timestamp"])
        timestamps = [e["timestamp"] for e in events]
        n = len(events)
        j = 0
        best: PasswordSprayFinding | None = None
        for i in range(n):
            if j < i:
                j = i
            while j < n and timestamps[j] - timestamps[i] <= window_seconds:
                j += 1
            window_events = events[i:j]
            src_counts: dict[str, int] = defaultdict(int)
            for we in window_events:
                src_counts[we["src_ip"]] += 1
            # a source already crossing the brute-force threshold on its
            # own belongs to that detector, not the "low and slow" one -
            # otherwise a loud single-source attack would also count as
            # a spray just by having many failures against one host
            if max(src_counts.values(), default=0) >= brute_force_threshold:
                continue
            distinct_sources = len(src_counts)
            if distinct_sources < min_distinct_sources:
                continue
            if best is None or distinct_sources > best.distinct_sources:
                best = PasswordSprayFinding(
                    target_host=host, window_start=window_events[0]["timestamp"],
                    window_end=window_events[-1]["timestamp"],
                    src_ips={we["src_ip"] for we in window_events},
                    usernames={we["username"] for we in window_events},
                )
        if best is not None:
            findings.append(best)

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
