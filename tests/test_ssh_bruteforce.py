from detection.ssh_bruteforce import detect_brute_force, detect_password_spray
from scenarios.generate import (
    generate_normal_population,
    inject_ssh_brute_force,
    inject_ssh_low_and_slow_spray,
)


def test_normal_ssh_traffic_triggers_neither_detector():
    data = generate_normal_population(num_users=15, days=10, seed=8)
    assert detect_brute_force(data["ssh_events"]) == []
    assert detect_password_spray(data["ssh_events"]) == []


def test_classic_brute_force_is_detected():
    data = generate_normal_population(num_users=2, days=2, seed=1)
    data["ssh_events"] = []
    inject_ssh_brute_force(data, num_attempts=40, seed=6)

    findings = detect_brute_force(data["ssh_events"])
    assert len(findings) == 1
    assert findings[0].attempt_count >= 30

    assert detect_password_spray(data["ssh_events"]) == []


def test_password_spray_is_detected_and_not_caught_by_brute_force():
    data = generate_normal_population(num_users=2, days=2, seed=1)
    data["ssh_events"] = []
    inject_ssh_low_and_slow_spray(data, num_sources=15, seed=7)

    assert detect_brute_force(data["ssh_events"]) == []

    findings = detect_password_spray(data["ssh_events"])
    assert len(findings) == 1
    assert findings[0].distinct_sources == 15
    assert len(findings[0].usernames) >= 1


def test_spray_with_too_few_sources_is_not_flagged():
    data = generate_normal_population(num_users=1, days=1, seed=1)
    data["ssh_events"] = []
    inject_ssh_low_and_slow_spray(data, num_sources=3, seed=7)
    assert detect_password_spray(data["ssh_events"]) == []
