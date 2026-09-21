"""Aggregation logic behind the SSH Brute Force Detection view
(/ssh-detection). Kept separate from web/app.py's routes and from
detection/ssh_bruteforce.py's actual detectors - this module only
reshapes real ssh_events into chart-friendly aggregates, it doesn't
decide what counts as an attack.
"""
from __future__ import annotations

from collections import defaultdict

from detection._util import as_dict
from detection.ssh_bruteforce import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS
from ingestion.geo_lookup import geo_for_ip

_SSH_FIELDS = ("event_id", "timestamp", "src_ip", "target_host", "username", "success")


def _failed_events(ssh_events) -> list[dict]:
    return [as_dict(e, _SSH_FIELDS) for e in ssh_events if not as_dict(e, _SSH_FIELDS)["success"]]


def build_timeline(ssh_events, bucket_seconds: float = BRUTE_FORCE_WINDOW_SECONDS) -> dict:
    failed = _failed_events(ssh_events)
    if not failed:
        return {"buckets": [], "alert_threshold": BRUTE_FORCE_THRESHOLD}

    counts: dict[int, int] = defaultdict(int)
    for e in failed:
        bucket = int(e["timestamp"] // bucket_seconds)
        counts[bucket] += 1

    buckets = [
        {"t": bucket * bucket_seconds, "count": count}
        for bucket, count in sorted(counts.items())
    ]
    return {"buckets": buckets, "alert_threshold": BRUTE_FORCE_THRESHOLD}


def _max_window_count(sorted_ts: list[float], window_seconds: float) -> int:
    n = len(sorted_ts)
    j = 0
    best = 0
    for i in range(n):
        if j < i:
            j = i
        while j < n and sorted_ts[j] - sorted_ts[i] <= window_seconds:
            j += 1
        best = max(best, j - i)
    return best


def build_top_attackers(ssh_events, limit: int = 10) -> list[dict]:
    failed = _failed_events(ssh_events)
    by_src: dict[str, list[dict]] = defaultdict(list)
    for e in failed:
        by_src[e["src_ip"]].append(e)

    rows = []
    for src_ip, events in by_src.items():
        events.sort(key=lambda e: e["timestamp"])
        geo = geo_for_ip(src_ip)
        rows.append({
            "src_ip": src_ip,
            "target_hosts": sorted({e["target_host"] for e in events}),
            "country": geo.country,
            "city": geo.city,
            "failed_count": len(events),
            "first_seen": events[0]["timestamp"],
            "last_seen": events[-1]["timestamp"],
        })

    rows.sort(key=lambda r: r["failed_count"], reverse=True)
    return rows[:limit]


def build_geo_summary(ssh_events) -> list[dict]:
    failed = _failed_events(ssh_events)
    by_country: dict[str, dict] = {}
    for e in failed:
        geo = geo_for_ip(e["src_ip"])
        key = geo.country
        if key not in by_country:
            by_country[key] = {
                "country": geo.country, "city": geo.city,
                "lat": geo.lat, "lon": geo.lon, "failed_count": 0,
            }
        by_country[key]["failed_count"] += 1

    return sorted(by_country.values(), key=lambda r: r["failed_count"], reverse=True)


def build_gauges(ssh_events, window_seconds: float = 60.0) -> list[dict]:
    """Real per-source peak rate, sorted - not tied to which detector
    (classic brute force vs. spray) a source happens to trip. The
    contrast between the top two is naturally the same "one loud
    attacker vs. many quiet ones" story the detectors are built to
    catch, without hardcoding which is which."""
    failed = _failed_events(ssh_events)
    by_src: dict[str, list[float]] = defaultdict(list)
    for e in failed:
        by_src[e["src_ip"]].append(e["timestamp"])

    rates = []
    for src_ip, timestamps in by_src.items():
        timestamps.sort()
        peak = _max_window_count(timestamps, window_seconds)
        rates.append({"src_ip": src_ip, "attempts_per_minute": round(peak * (60.0 / window_seconds), 1)})

    rates.sort(key=lambda r: r["attempts_per_minute"], reverse=True)
    return rates[:2]
