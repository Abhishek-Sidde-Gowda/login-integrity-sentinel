import uuid

from detection.token_fork import detect_forks
from ingestion.schema import TokenEvent
from scenarios.generate import generate_normal_population, inject_token_fork


def _token(token_id, user_id, ts, ip, device, ttype, parent=None):
    return TokenEvent(token_id=token_id, user_id=user_id, session_id="s1", issued_at=ts,
                       issued_ip=ip, issued_device=device, token_type=ttype, parent_token_id=parent)


def test_normal_population_produces_no_forks():
    data = generate_normal_population(num_users=15, days=10, seed=6)
    findings = detect_forks(data["token_events"])
    assert findings == []


def test_injected_token_fork_is_detected():
    data = generate_normal_population(num_users=1, days=1, seed=1)
    inject_token_fork(data, num_cases=5, seed=11)
    findings = detect_forks(data["token_events"])
    assert len(findings) == 5
    for f in findings:
        assert len(f.device_ip_pairs) == 2
        assert ("10.10.1.50", "legit-device") in f.device_ip_pairs
        assert f.time_span_seconds <= 60.0


def test_multiple_access_tokens_same_device_is_not_a_fork():
    refresh = _token("r1", "u1", 0, "10.10.1.5", "laptop", "refresh")
    child1 = _token("c1", "u1", 5, "10.10.1.5", "laptop", "access", parent="r1")
    child2 = _token("c2", "u1", 10, "10.10.1.5", "laptop", "access", parent="r1")
    findings = detect_forks([refresh, child1, child2])
    assert findings == []


def test_children_far_apart_in_time_are_not_flagged():
    refresh = _token("r1", "u1", 0, "10.10.1.5", "laptop", "refresh")
    child1 = _token("c1", "u1", 10, "10.10.1.5", "laptop", "access", parent="r1")
    child2 = _token("c2", "u1", 10_000, "45.83.1.9", "attacker-box", "access", parent="r1")
    findings = detect_forks([refresh, child1, child2], window_seconds=60.0)
    assert findings == []


def test_single_child_is_never_a_fork():
    refresh = _token("r1", "u1", 0, "10.10.1.5", "laptop", "refresh")
    child1 = _token("c1", "u1", 5, "10.10.1.5", "laptop", "access", parent="r1")
    findings = detect_forks([refresh, child1])
    assert findings == []
