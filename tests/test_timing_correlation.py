from detection.timing_correlation import detect_bursts
from scenarios.generate import generate_normal_population, inject_credential_farm


def test_normal_population_produces_no_bursts():
    data = generate_normal_population(num_users=30, days=14, seed=42)
    bursts = detect_bursts(data["auth_events"])
    assert bursts == []


def test_credential_farm_is_detected_as_a_high_risk_burst():
    data = generate_normal_population(num_users=10, days=5, seed=1)
    inject_credential_farm(data, num_accounts=25, bursts=6, seed=2)

    bursts = detect_bursts(data["auth_events"])
    assert bursts, "expected at least one burst detected"

    top = bursts[0]
    assert top.size >= 20  # most/all of the 25 farm accounts landed in one window
    assert all(u.startswith("farmvictim") for u in top.user_ids)
    assert top.z_score == float("inf") or top.z_score > 3.0


def test_recurring_burst_is_flagged_and_scored_higher():
    data = generate_normal_population(num_users=10, days=5, seed=1)
    inject_credential_farm(data, num_accounts=25, bursts=6, seed=2)

    bursts = detect_bursts(data["auth_events"])
    recurring = [b for b in bursts if b.is_recurring]
    assert recurring, "the same 25-account farm repeating across 6 bursts should be flagged as recurring"
    for b in recurring:
        assert b.recurrence_matches
        assert b.risk_score == b.z_score * 2.0


def test_small_incidental_overlap_below_threshold_is_ignored():
    data = generate_normal_population(num_users=3, days=1, seed=7)
    bursts = detect_bursts(data["auth_events"], min_burst_size=4)
    assert bursts == []
