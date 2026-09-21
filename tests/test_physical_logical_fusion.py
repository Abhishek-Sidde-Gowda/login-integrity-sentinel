import uuid

from detection.physical_logical_fusion import detect_mismatches
from ingestion.schema import AuthEvent, BadgeEvent
from scenarios.generate import generate_normal_population, inject_physical_logical_mismatch


def _auth(user_id, ts, src_ip):
    return AuthEvent(
        event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts, src_ip=src_ip,
        device_fingerprint="d", user_agent="ua", geo_country="US", geo_city="c",
        session_id=uuid.uuid4().hex,
    )


def _badge(user_id, ts, building):
    return BadgeEvent(event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts,
                       reader_id=f"{building}-lobby", building=building, floor="1")


def test_normal_population_has_no_mismatches():
    data = generate_normal_population(num_users=15, days=10, seed=3)
    mismatches = detect_mismatches(data["auth_events"], data["badge_events"])
    assert mismatches == []


def test_injected_mismatch_is_detected():
    data = generate_normal_population(num_users=1, days=1, seed=1)
    inject_physical_logical_mismatch(data, num_cases=5, seed=9)
    mismatches = detect_mismatches(data["auth_events"], data["badge_events"])
    assert len(mismatches) == 5
    for m in mismatches:
        assert m.badge_building == "HQ-North"
        assert m.login_building == "HQ-South"
        assert 0 <= m.gap_seconds <= 4 * 3600


def test_stale_badge_read_outside_window_is_not_flagged():
    user_id = "user999"
    badge = _badge(user_id, ts=0, building="HQ-North")
    stale_login = _auth(user_id, ts=5 * 3600, src_ip="10.10.2.50")  # 5h later, HQ-South segment
    mismatches = detect_mismatches([stale_login], [badge])
    assert mismatches == []


def test_recent_badge_read_with_different_building_is_flagged():
    user_id = "user999"
    badge = _badge(user_id, ts=0, building="HQ-North")
    login = _auth(user_id, ts=3600, src_ip="10.10.2.50")  # 1h later, HQ-South segment
    mismatches = detect_mismatches([login], [badge])
    assert len(mismatches) == 1
    assert mismatches[0].gap_seconds == 3600


def test_login_from_unmapped_ip_is_not_flagged():
    """A login from an IP outside any known building segment (home
    internet, unmanaged network) makes no physical claim to contradict -
    this must not be treated the same as a same-building match."""
    user_id = "user999"
    badge = _badge(user_id, ts=0, building="HQ-North")
    login = _auth(user_id, ts=60, src_ip="203.0.113.44")
    mismatches = detect_mismatches([login], [badge])
    assert mismatches == []


def test_user_with_no_badge_history_is_not_flagged():
    login = _auth("ghost_user", ts=100, src_ip="10.10.2.5")
    mismatches = detect_mismatches([login], [])
    assert mismatches == []
