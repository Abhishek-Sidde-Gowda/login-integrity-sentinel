"""Building <-> network segment mapping.

In production this would come from a CMDB/IPAM asset inventory, not a
hardcoded dict - kept here (rather than in scenarios/) so the physical-
logical fusion detector and the synthetic data generator share one
definition instead of two that could silently drift apart.
"""
from __future__ import annotations

BUILDING_NETWORK_SEGMENTS = {
    "HQ-North": "10.10.1.",
    "HQ-South": "10.10.2.",
    "Remote-VPN": "10.50.0.",
}


def building_for_ip(ip: str) -> str | None:
    for building, prefix in BUILDING_NETWORK_SEGMENTS.items():
        if ip.startswith(prefix):
            return building
    return None
