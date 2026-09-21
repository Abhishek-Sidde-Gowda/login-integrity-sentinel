from pathlib import Path

import pytest

from ingestion.store import Store
from scenarios.generate import (
    build_full_dataset,
    generate_normal_population,
    inject_credential_farm,
    inject_evasion_proxy,
    inject_physical_logical_mismatch,
    inject_ssh_brute_force,
    inject_ssh_low_and_slow_spray,
    inject_token_fork,
)


@pytest.fixture
def tmp_store(tmp_path: Path) -> Store:
    store = Store(db_path=tmp_path / "test.db")
    yield store
    store.close()


def test_normal_population_has_matched_badge_and_login_buildings():
    data = generate_normal_population(num_users=5, days=5)
    assert data["auth_events"]
    assert data["badge_events"]
    # every normal auth event's src_ip prefix should match some badge
    # building prefix for the same user (no injected mismatch yet)
    badge_prefixes = {b.user_id: b.building for b in data["badge_events"]}
    from scenarios.generate import BUILDINGS
    for auth in data["auth_events"]:
        building = badge_prefixes.get(auth.user_id)
        assert building is not None
        assert auth.src_ip.startswith(BUILDINGS[building])


def test_credential_farm_injects_synchronized_cross_account_bursts():
    data = generate_normal_population(num_users=2, days=2)
    before = len(data["auth_events"])
    inject_credential_farm(data, num_accounts=10, bursts=2)
    assert len(data["auth_events"]) == before + 20
    farm_events = [e for e in data["auth_events"] if e.user_id.startswith("farmvictim")]
    timestamps = sorted(e.timestamp for e in farm_events[:10])
    assert timestamps[-1] - timestamps[0] < 5  # tight synchronized window


def test_physical_logical_mismatch_produces_building_disagreement():
    data = generate_normal_population(num_users=1, days=1)
    inject_physical_logical_mismatch(data, num_cases=3)
    mismatches = [a for a in data["auth_events"] if a.device_fingerprint == "unrecognized-device"]
    assert len(mismatches) == 3


def test_evasion_proxy_rtt_exceeds_distance_expectation():
    data = generate_normal_population(num_users=1, days=1)
    inject_evasion_proxy(data, num_cases=4)
    proxy_fps = [f for f in data["fingerprints"] if f.ja3_hash == "proxy-ja3-variant"]
    assert len(proxy_fps) == 4
    for fp in proxy_fps:
        assert fp.measured_rtt_ms > fp.expected_rtt_ms_for_distance * 3


def test_token_fork_child_tokens_diverge_from_parent_device():
    data = generate_normal_population(num_users=1, days=1)
    inject_token_fork(data, num_cases=2)
    forked = [t for t in data["token_events"] if t.issued_device == "attacker-device"]
    assert len(forked) == 2
    for tok in forked:
        parent = next(t for t in data["token_events"] if t.token_id == tok.parent_token_id)
        assert parent.issued_device != tok.issued_device


def test_ssh_brute_force_is_single_source_single_account():
    data = generate_normal_population(num_users=1, days=1)
    data["ssh_events"] = []
    inject_ssh_brute_force(data, num_attempts=30)
    sources = {e.src_ip for e in data["ssh_events"]}
    usernames = {e.username for e in data["ssh_events"]}
    assert len(sources) == 1
    assert len(usernames) == 1
    assert sum(1 for e in data["ssh_events"] if not e.success) == 29


def test_ssh_low_and_slow_spray_fans_out_across_many_sources():
    data = generate_normal_population(num_users=1, days=1)
    data["ssh_events"] = []
    inject_ssh_low_and_slow_spray(data, num_sources=12)
    sources = {e.src_ip for e in data["ssh_events"]}
    per_source_counts = {}
    for e in data["ssh_events"]:
        per_source_counts[e.src_ip] = per_source_counts.get(e.src_ip, 0) + 1
    assert len(sources) == 12
    # the whole point: no single source crosses a naive "brute force" count
    assert max(per_source_counts.values()) <= 3


def test_full_dataset_round_trips_through_sqlite_store(tmp_store: Store):
    data = build_full_dataset()
    tmp_store.insert_auth_events(data["auth_events"])
    tmp_store.insert_badge_events(data["badge_events"])
    tmp_store.insert_token_events(data["token_events"])
    tmp_store.insert_network_fingerprints(data["fingerprints"])
    tmp_store.insert_ssh_events(data["ssh_events"])

    assert len(tmp_store.all_auth_events()) == len(data["auth_events"])
    assert len(tmp_store.all_badge_events()) == len(data["badge_events"])
    assert len(tmp_store.all_token_events()) == len(data["token_events"])
    assert len(tmp_store.all_network_fingerprints()) == len(data["fingerprints"])
    assert len(tmp_store.all_ssh_events()) == len(data["ssh_events"])
