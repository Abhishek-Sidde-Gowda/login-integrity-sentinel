from scenarios.generate import (
    generate_normal_population,
    inject_ssh_brute_force,
    inject_ssh_low_and_slow_spray,
)
from web.ssh_dashboard import build_gauges, build_geo_summary, build_timeline, build_top_attackers


def _dataset():
    data = generate_normal_population(num_users=2, days=2, seed=1)
    data["ssh_events"] = []
    inject_ssh_brute_force(data, num_attempts=40, seed=6)
    inject_ssh_low_and_slow_spray(data, num_sources=15, seed=7)
    return data


def test_timeline_only_counts_failed_attempts_and_carries_threshold():
    data = _dataset()
    timeline = build_timeline(data["ssh_events"])
    assert timeline["alert_threshold"] == 10
    assert sum(b["count"] for b in timeline["buckets"]) == sum(
        1 for e in data["ssh_events"] if not e.success
    )


def test_top_attackers_ranks_brute_force_source_first():
    data = _dataset()
    top = build_top_attackers(data["ssh_events"])
    assert top[0]["src_ip"] == "45.83.64.204"
    assert top[0]["failed_count"] == 39
    assert top[0]["country"] == "Netherlands"


def test_geo_summary_aggregates_by_illustrative_country():
    data = _dataset()
    summary = build_geo_summary(data["ssh_events"])
    countries = {row["country"] for row in summary}
    assert "Netherlands" in countries  # 45.83.64.x
    assert "Germany" in countries      # 185.220.x.x
    total = sum(row["failed_count"] for row in summary)
    assert total == sum(1 for e in data["ssh_events"] if not e.success)


def test_gauges_show_loud_attacker_far_above_quiet_ones():
    data = _dataset()
    gauges = build_gauges(data["ssh_events"])
    assert len(gauges) == 2
    assert gauges[0]["src_ip"] == "45.83.64.204"
    assert gauges[0]["attempts_per_minute"] > gauges[1]["attempts_per_minute"] * 5


def test_empty_ssh_events_produce_empty_aggregates():
    assert build_timeline([]) == {"buckets": [], "alert_threshold": 10}
    assert build_top_attackers([]) == []
    assert build_geo_summary([]) == []
    assert build_gauges([]) == []
