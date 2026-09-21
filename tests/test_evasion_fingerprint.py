import uuid

from detection.evasion_fingerprint import detect_evasion
from ingestion.schema import AuthEvent, NetworkFingerprint
from scenarios.generate import generate_normal_population, inject_evasion_proxy


def _auth(event_id, user_id="u1"):
    return AuthEvent(
        event_id=event_id, user_id=user_id, timestamp=0, src_ip="10.10.1.5",
        device_fingerprint="d", user_agent="ua", geo_country="US", geo_city="c",
        session_id=uuid.uuid4().hex,
    )


def test_normal_population_produces_no_evasion_flags():
    data = generate_normal_population(num_users=20, days=10, seed=5)
    flags = detect_evasion(data["auth_events"], data["fingerprints"])
    assert flags == []


def test_injected_proxy_cases_are_all_flagged():
    data = generate_normal_population(num_users=1, days=1, seed=1)
    inject_evasion_proxy(data, num_cases=6, seed=4)
    flags = detect_evasion(data["auth_events"], data["fingerprints"])
    proxy_event_ids = {fp.event_id for fp in data["fingerprints"] if fp.ja3_hash == "proxy-ja3-variant"}
    flagged_ids = {f.event_id for f in flags}
    assert proxy_event_ids <= flagged_ids


def test_plausible_local_rtt_is_not_flagged():
    event_id = uuid.uuid4().hex
    fp = NetworkFingerprint(event_id=event_id, measured_rtt_ms=8.0, ttl=64,
                             ja3_hash="normal", claimed_geo_distance_km=2.0)
    flags = detect_evasion([_auth(event_id)], [fp])
    assert flags == []


def test_rtt_far_beyond_claimed_distance_is_flagged():
    event_id = uuid.uuid4().hex
    fp = NetworkFingerprint(event_id=event_id, measured_rtt_ms=250.0, ttl=51,
                             ja3_hash="suspicious", claimed_geo_distance_km=3.0)
    flags = detect_evasion([_auth(event_id, "victim")], [fp])
    assert len(flags) == 1
    assert flags[0].user_id == "victim"
    assert flags[0].rtt_ratio == 50.0  # 250 / expected floor of 5.0


def test_low_ttl_corroboration_raises_risk_score_over_high_ttl_case():
    id_a, id_b = uuid.uuid4().hex, uuid.uuid4().hex
    same_ratio_high_ttl = NetworkFingerprint(event_id=id_a, measured_rtt_ms=50.0, ttl=60,
                                              ja3_hash="x", claimed_geo_distance_km=1.0)
    same_ratio_low_ttl = NetworkFingerprint(event_id=id_b, measured_rtt_ms=50.0, ttl=45,
                                             ja3_hash="x", claimed_geo_distance_km=1.0)
    flags = detect_evasion([_auth(id_a), _auth(id_b)], [same_ratio_high_ttl, same_ratio_low_ttl])
    by_id = {f.event_id: f for f in flags}
    assert by_id[id_b].risk_score > by_id[id_a].risk_score
