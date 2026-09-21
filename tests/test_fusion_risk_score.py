import uuid

from fusion.risk_score import SIGNAL_SCORE_CAP, _clamp, compute_host_risk, compute_identity_risk
from ingestion.schema import AuthEvent, BadgeEvent, NetworkFingerprint
from scenarios.generate import (
    build_full_dataset,
    generate_normal_population,
    inject_credential_farm,
    inject_ssh_brute_force,
    inject_ssh_low_and_slow_spray,
)


def _auth(user_id, ts, src_ip):
    return AuthEvent(event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts, src_ip=src_ip,
                      device_fingerprint="d", user_agent="ua", geo_country="US", geo_city="c",
                      session_id=uuid.uuid4().hex)


def test_clean_population_produces_no_risk_scores():
    data = generate_normal_population(num_users=15, days=10, seed=20)
    identity_scores = compute_identity_risk(
        data["auth_events"], data["badge_events"], data["fingerprints"], data["token_events"]
    )
    host_scores = compute_host_risk(data["ssh_events"])
    assert identity_scores == []
    assert host_scores == []


def test_credential_farm_users_score_on_one_signal():
    data = generate_normal_population(num_users=5, days=2, seed=1)
    inject_credential_farm(data, num_accounts=10, bursts=1, seed=2)
    scores = compute_identity_risk(data["auth_events"], data["badge_events"], data["fingerprints"], data["token_events"])
    farm_scores = [s for s in scores if s.identity_id.startswith("farmvictim")]
    assert len(farm_scores) == 10
    for s in farm_scores:
        assert s.num_signals_tripped == 1
        assert "cross_account_timing" in s.signal_scores
        assert s.total_score == s.signal_scores["cross_account_timing"]


def test_multi_signal_identity_gets_multiplicative_agreement_bonus():
    user_id = "multiuser"
    badge = BadgeEvent(event_id=uuid.uuid4().hex, user_id=user_id, timestamp=0,
                        reader_id="HQ-North-lobby", building="HQ-North", floor="1")
    mismatch_login = _auth(user_id, ts=60, src_ip="10.10.2.50")  # HQ-South segment -> mismatch

    evasion_login = _auth(user_id, ts=200, src_ip="10.10.1.5")
    fp = NetworkFingerprint(event_id=evasion_login.event_id, measured_rtt_ms=250.0, ttl=51,
                             ja3_hash="proxy", claimed_geo_distance_km=2.0)

    scores = compute_identity_risk(
        auth_events=[mismatch_login, evasion_login],
        badge_events=[badge], fingerprints=[fp], token_events=[],
    )
    assert len(scores) == 1
    s = scores[0]
    assert s.identity_id == user_id
    assert s.num_signals_tripped == 2
    additive = s.signal_scores["physical_logical"] + s.signal_scores["evasion_fingerprint"]
    assert s.total_score == additive * 1.5


def test_ssh_signals_score_hosts_not_identities():
    data = generate_normal_population(num_users=2, days=2, seed=1)
    data["ssh_events"] = []
    inject_ssh_brute_force(data, num_attempts=40, seed=6)
    inject_ssh_low_and_slow_spray(data, num_sources=15, seed=7)

    identity_scores = compute_identity_risk(data["auth_events"], data["badge_events"], data["fingerprints"], data["token_events"])
    host_scores = compute_host_risk(data["ssh_events"])

    assert identity_scores == []  # SSH signals never touch identity scoring
    assert len(host_scores) >= 1
    assert all(hs.host_id for hs in host_scores)


def test_infinite_zscore_burst_is_clamped_to_a_finite_total():
    isolated = [_auth(f"solo{i}", ts=i * 3600, src_ip="10.10.1.5") for i in range(5)]
    burst = [_auth(f"farm{i}", ts=100000 + i * 0.1, src_ip="198.51.100.1") for i in range(6)]

    scores = compute_identity_risk(isolated + burst, [], [], [])
    farm_scores = [s for s in scores if s.identity_id.startswith("farm")]
    assert farm_scores
    for s in farm_scores:
        assert s.signal_scores["cross_account_timing"] == SIGNAL_SCORE_CAP
        assert s.total_score < float("inf")


def test_clamp_helper():
    assert _clamp(float("inf")) == SIGNAL_SCORE_CAP
    assert _clamp(10.0) == 10.0
    assert _clamp(-5.0) == 0.0
    assert _clamp(SIGNAL_SCORE_CAP + 100) == SIGNAL_SCORE_CAP


def test_full_dataset_fusion_runs_end_to_end_without_error():
    data = build_full_dataset()
    identity_scores = compute_identity_risk(
        data["auth_events"], data["badge_events"], data["fingerprints"], data["token_events"]
    )
    host_scores = compute_host_risk(data["ssh_events"])
    assert identity_scores
    assert host_scores
    # sorted descending by total_score
    assert all(identity_scores[i].total_score >= identity_scores[i + 1].total_score
               for i in range(len(identity_scores) - 1))
