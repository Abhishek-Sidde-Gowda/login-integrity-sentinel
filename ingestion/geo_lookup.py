"""Illustrative IP -> geolocation lookup for the SSH attack-map view.

This is a small static prefix table, NOT a real GeoIP database
integration (no MaxMind/ip-api/etc. call, no license, no accuracy
claim) - it exists only so the dashboard's map/table have somewhere to
plot the synthetic attacker IPs scenarios/generate.py already uses.
Real-world reference ranges are used where one exists (185.220.100-110.x
is a well-known Tor exit-relay range, commonly hosted in Germany/
Netherlands) so the demo isn't placing dots at fictional coordinates
for no reason; 198.51.100.x and 203.0.113.x are IANA TEST-NET ranges
that don't route anywhere real, so their "location" here is frankly
illustrative and labeled as a demo range in the label text itself.

A real deployment would replace this module with an actual GeoIP
lookup (MaxMind GeoLite2, ipinfo.io, etc.) behind the same
`geo_for_ip()` signature - nothing downstream cares how the lookup is
implemented.
"""
from __future__ import annotations

from dataclasses import dataclass

UNKNOWN = "Unknown"

_PREFIX_TABLE: list[tuple[str, dict]] = [
    ("45.83.64.", {"country": "Netherlands", "city": "Amsterdam", "lat": 52.37, "lon": 4.90}),
    ("185.220.", {"country": "Germany", "city": "Frankfurt", "lat": 50.11, "lon": 8.68}),
    ("198.51.100.", {"country": "Demo range (TEST-NET-2)", "city": "n/a", "lat": 47.0, "lon": 25.0}),
    ("203.0.113.", {"country": "Demo range (TEST-NET-3)", "city": "n/a", "lat": 39.0, "lon": -77.0}),
    ("10.", {"country": "Internal", "city": "n/a", "lat": None, "lon": None}),
]


@dataclass
class GeoLocation:
    country: str
    city: str
    lat: float | None
    lon: float | None


def geo_for_ip(ip: str) -> GeoLocation:
    for prefix, info in _PREFIX_TABLE:
        if ip.startswith(prefix):
            return GeoLocation(**info)
    return GeoLocation(country=UNKNOWN, city="n/a", lat=None, lon=None)
