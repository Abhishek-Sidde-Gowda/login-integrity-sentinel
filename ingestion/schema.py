"""Event schemas shared by ingestion, scenarios, and detection.

Four event types back the four fused signals:
  AuthEvent    - login attempts (cross-account timing, evasion detector)
  BadgeEvent   - simulated physical access reads (physical-logical fusion)
  TokenEvent   - OAuth token issuance/refresh lineage (fork detection)
  NetworkFingerprint - per-auth network measurements (evasion detector)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthEvent:
    event_id: str
    user_id: str
    timestamp: float  # unix epoch seconds
    src_ip: str
    device_fingerprint: str
    user_agent: str
    geo_country: str
    geo_city: str
    session_id: str
    success: bool = True


@dataclass
class BadgeEvent:
    """Simulated - no physical reader hardware in this portfolio yet.

    Mirrors what rfid-usb-correlation-engine would emit once it has real
    hardware; kept as a separate, clearly-synthetic event stream so this
    tool never claims a live physical-access integration it doesn't have.
    """
    event_id: str
    user_id: str
    timestamp: float
    reader_id: str
    building: str
    floor: str


@dataclass
class TokenEvent:
    token_id: str
    user_id: str
    session_id: str
    issued_at: float
    issued_ip: str
    issued_device: str
    token_type: str  # "refresh" | "access"
    parent_token_id: Optional[str] = None


@dataclass
class SSHAuthEvent:
    """sshd-style auth attempt (real journalctl/auth.log parsing lands in
    ingestion/ssh_parser.py; scenarios/generate.py synthesizes these for
    now, same honesty pattern as BadgeEvent)."""
    event_id: str
    timestamp: float
    src_ip: str
    target_host: str
    username: str
    success: bool


@dataclass
class NetworkFingerprint:
    event_id: str  # foreign key -> AuthEvent.event_id
    measured_rtt_ms: float
    ttl: int
    ja3_hash: str
    claimed_geo_distance_km: float
    expected_rtt_ms_for_distance: float = field(init=False)

    def __post_init__(self) -> None:
        # ~1ms per 100km of great-circle distance is a rough real-world
        # floor for terrestrial routing latency (speed-of-light-in-fiber
        # plus routing overhead); used only as a sanity floor, not a
        # precise geolocation-from-latency model.
        self.expected_rtt_ms_for_distance = max(5.0, self.claimed_geo_distance_km / 100.0)
