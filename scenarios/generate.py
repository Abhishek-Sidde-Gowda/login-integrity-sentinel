"""Synthetic dataset generator: a normal population plus four injected
attack patterns, one per fused signal. All badge data is explicitly
synthetic (see ingestion/schema.py::BadgeEvent) - there is no real
reader hardware in this portfolio yet.
"""
from __future__ import annotations

import random
import time
import uuid
from dataclasses import replace

from ingestion.network_topology import BUILDING_NETWORK_SEGMENTS as BUILDINGS
from ingestion.schema import AuthEvent, BadgeEvent, NetworkFingerprint, SSHAuthEvent, TokenEvent

SSH_HOSTS = ["bastion-01", "app-db-03", "web-edge-07"]
COMMON_USERNAMES = ["root", "admin", "ubuntu", "deploy", "postgres", "svc-backup", "jenkins"]

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]


def _now_minus_days(days: float) -> float:
    return time.time() - days * 86400


def _ip_in(building: str, host: int) -> str:
    return f"{BUILDINGS[building]}{host}"


def generate_normal_population(num_users: int = 30, days: int = 14, seed: int = 1) -> dict:
    rng = random.Random(seed)
    auth_events, badge_events, token_events, fingerprints = [], [], [], []

    for u in range(num_users):
        user_id = f"user{u:03d}"
        home_building = rng.choice(list(BUILDINGS))
        device = f"device-{uuid.uuid4().hex[:8]}"
        ua = rng.choice(UA_POOL)

        for d in range(days):
            if rng.random() < 0.15:
                continue  # day off
            ts = _now_minus_days(days - d) + rng.uniform(8, 10) * 3600
            session_id = uuid.uuid4().hex

            badge_events.append(BadgeEvent(
                event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts - 120,
                reader_id=f"{home_building}-lobby", building=home_building, floor="1",
            ))

            event_id = uuid.uuid4().hex
            auth_events.append(AuthEvent(
                event_id=event_id, user_id=user_id, timestamp=ts,
                src_ip=_ip_in(home_building, rng.randint(10, 250)),
                device_fingerprint=device, user_agent=ua,
                geo_country="US", geo_city="Springfield", session_id=session_id,
            ))
            fingerprints.append(NetworkFingerprint(
                event_id=event_id, measured_rtt_ms=rng.uniform(5, 15),
                ttl=64, ja3_hash="normal-ja3-fixed",
                claimed_geo_distance_km=rng.uniform(0, 5),
            ))

            refresh_id = uuid.uuid4().hex
            token_events.append(TokenEvent(
                token_id=refresh_id, user_id=user_id, session_id=session_id,
                issued_at=ts, issued_ip=auth_events[-1].src_ip, issued_device=device,
                token_type="refresh",
            ))
            token_events.append(TokenEvent(
                token_id=uuid.uuid4().hex, user_id=user_id, session_id=session_id,
                issued_at=ts + 5, issued_ip=auth_events[-1].src_ip, issued_device=device,
                token_type="access", parent_token_id=refresh_id,
            ))

    ssh_events = []
    for d in range(days):
        if rng.random() < 0.7:
            continue  # ssh access is rarer than web login
        ts = _now_minus_days(days - d) + rng.uniform(9, 17) * 3600
        ssh_events.append(SSHAuthEvent(
            event_id=uuid.uuid4().hex, timestamp=ts,
            src_ip=_ip_in("HQ-North", rng.randint(10, 250)),
            target_host=rng.choice(SSH_HOSTS), username="deploy", success=True,
        ))

    return {
        "auth_events": auth_events, "badge_events": badge_events,
        "token_events": token_events, "fingerprints": fingerprints,
        "ssh_events": ssh_events,
    }


def inject_ssh_brute_force(data: dict, num_attempts: int = 40, seed: int = 6) -> None:
    """Classic brute force: one source IP hammers one account with many
    failed attempts in a tight window, then (sometimes) a success. Easy
    to catch with a naive per-IP failure-count threshold - included as
    the baseline case the low-and-slow variant below is designed to beat."""
    rng = random.Random(seed)
    src_ip = f"45.83.64.{rng.randint(1, 254)}"
    host = rng.choice(SSH_HOSTS)
    ts = _now_minus_days(rng.uniform(0, 5))
    for i in range(num_attempts):
        data["ssh_events"].append(SSHAuthEvent(
            event_id=uuid.uuid4().hex, timestamp=ts + i * 2.0,
            src_ip=src_ip, target_host=host, username="root",
            success=(i == num_attempts - 1),
        ))


def inject_ssh_low_and_slow_spray(data: dict, num_sources: int = 15, seed: int = 7) -> None:
    """Password spraying, spread thin on purpose: many distinct source
    IPs, each trying a handful of common usernames a few times over
    several hours - no single IP or username crosses a naive per-entity
    failure threshold. What stands out instead is the population-level
    pattern: an unusually wide fan-out of (src_ip, username) pairs all
    failing against the SAME target_host in the same window, which is
    the signal a per-account or per-IP rule structurally can't see."""
    rng = random.Random(seed)
    host = rng.choice(SSH_HOSTS)
    window_start = _now_minus_days(rng.uniform(0, 5))
    for i in range(num_sources):
        src_ip = f"185.220.{rng.randint(100, 110)}.{rng.randint(1, 254)}"
        for username in rng.sample(COMMON_USERNAMES, k=rng.randint(1, 3)):
            data["ssh_events"].append(SSHAuthEvent(
                event_id=uuid.uuid4().hex,
                timestamp=window_start + rng.uniform(0, 4 * 3600),
                src_ip=src_ip, target_host=host, username=username, success=False,
            ))


def inject_credential_farm(data: dict, num_accounts: int = 25, bursts: int = 6, seed: int = 2) -> None:
    """Signal: cross-account synchronized login timing. Many unrelated
    accounts authenticate within a tight window, repeated over days -
    the fingerprint of one actor cycling a stolen-credential stash."""
    rng = random.Random(seed)
    for b in range(bursts):
        burst_ts = _now_minus_days(bursts - b) + rng.uniform(1, 3) * 3600
        for i in range(num_accounts):
            user_id = f"farmvictim{i:03d}"
            jitter = rng.uniform(0, 2.5)  # seconds - the "heartbeat"
            event_id = uuid.uuid4().hex
            data["auth_events"].append(AuthEvent(
                event_id=event_id, user_id=user_id, timestamp=burst_ts + jitter,
                src_ip=f"198.51.100.{rng.randint(1, 254)}",
                device_fingerprint=f"farm-device-{i}", user_agent=rng.choice(UA_POOL),
                geo_country="RO", geo_city="Unknown", session_id=uuid.uuid4().hex,
            ))


def inject_physical_logical_mismatch(data: dict, num_cases: int = 5, seed: int = 3) -> None:
    """Signal: physical-logical fusion. Badge places the user in one
    building; moments later a login originates from a network segment
    mapped to a different building - stronger than IP-only impossible
    travel since physical presence can't be proxied."""
    rng = random.Random(seed)
    for i in range(num_cases):
        user_id = f"user{i:03d}"
        badge_building = "HQ-North"
        login_building = "HQ-South"
        ts = _now_minus_days(rng.uniform(0, 10))

        data["badge_events"].append(BadgeEvent(
            event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts,
            reader_id=f"{badge_building}-lobby", building=badge_building, floor="1",
        ))
        data["auth_events"].append(AuthEvent(
            event_id=uuid.uuid4().hex, user_id=user_id, timestamp=ts + 90,
            src_ip=_ip_in(login_building, rng.randint(10, 250)),
            device_fingerprint="unrecognized-device", user_agent=rng.choice(UA_POOL),
            geo_country="US", geo_city="Springfield", session_id=uuid.uuid4().hex,
        ))


def inject_evasion_proxy(data: dict, num_cases: int = 5, seed: int = 4) -> None:
    """Signal: evasion-aware concurrency detector. Claimed geolocation
    looks local (low claimed_geo_distance_km) but measured RTT is far
    higher than physically plausible for that distance - consistent
    with a residential-proxy relay spoofing geolocation."""
    rng = random.Random(seed)
    for i in range(num_cases):
        user_id = f"user{(i + 10):03d}"
        event_id = uuid.uuid4().hex
        ts = _now_minus_days(rng.uniform(0, 10))
        data["auth_events"].append(AuthEvent(
            event_id=event_id, user_id=user_id, timestamp=ts,
            src_ip=f"203.0.113.{rng.randint(1, 254)}",
            device_fingerprint="proxy-device", user_agent=rng.choice(UA_POOL),
            geo_country="US", geo_city="Springfield", session_id=uuid.uuid4().hex,
        ))
        data["fingerprints"].append(NetworkFingerprint(
            event_id=event_id, measured_rtt_ms=rng.uniform(220, 320),  # far too high for "local"
            ttl=51, ja3_hash="proxy-ja3-variant",
            claimed_geo_distance_km=rng.uniform(1, 8),  # claims to be nearby
        ))


def inject_token_fork(data: dict, num_cases: int = 5, seed: int = 5) -> None:
    """Signal: session-token fork detection. One refresh token spawns
    two access tokens used from divergent device/IP pairs at nearly
    the same time - a legitimate client never forks a token this way."""
    rng = random.Random(seed)
    for i in range(num_cases):
        user_id = f"user{(i + 20):03d}"
        session_id = uuid.uuid4().hex
        ts = _now_minus_days(rng.uniform(0, 10))
        refresh_id = uuid.uuid4().hex
        data["token_events"].append(TokenEvent(
            token_id=refresh_id, user_id=user_id, session_id=session_id,
            issued_at=ts, issued_ip="10.10.1.50", issued_device="legit-device",
            token_type="refresh",
        ))
        # legitimate child
        data["token_events"].append(TokenEvent(
            token_id=uuid.uuid4().hex, user_id=user_id, session_id=session_id,
            issued_at=ts + 5, issued_ip="10.10.1.50", issued_device="legit-device",
            token_type="access", parent_token_id=refresh_id,
        ))
        # stolen-token replay: same refresh token, divergent device/IP, seconds later
        data["token_events"].append(TokenEvent(
            token_id=uuid.uuid4().hex, user_id=user_id, session_id=session_id,
            issued_at=ts + 8, issued_ip=f"185.220.101.{rng.randint(1, 254)}",
            issued_device="attacker-device", token_type="access",
            parent_token_id=refresh_id,
        ))


def build_full_dataset() -> dict:
    data = generate_normal_population()
    inject_credential_farm(data)
    inject_physical_logical_mismatch(data)
    inject_evasion_proxy(data)
    inject_token_fork(data)
    inject_ssh_brute_force(data)
    inject_ssh_low_and_slow_spray(data)
    return data
