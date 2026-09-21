"""SQLite mirror store for local processing/detection.

Splunk is the system of record for search/correlation (see
ingestion/splunk_client.py); this store exists so the Python detection
layer can run fast, dependency-free queries (joins, window functions)
without round-tripping through SPL for every computation, matching the
pattern used by the rest of the portfolio (e.g. iam-drift-sentinel).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from ingestion.schema import AuthEvent, BadgeEvent, NetworkFingerprint, SSHAuthEvent, TokenEvent

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "login_integrity.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_events (
    event_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    src_ip TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    geo_country TEXT NOT NULL,
    geo_city TEXT NOT NULL,
    session_id TEXT NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(user_id);

CREATE TABLE IF NOT EXISTS badge_events (
    event_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    reader_id TEXT NOT NULL,
    building TEXT NOT NULL,
    floor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_badge_events_ts ON badge_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_badge_events_user ON badge_events(user_id);

CREATE TABLE IF NOT EXISTS token_events (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    issued_ip TEXT NOT NULL,
    issued_device TEXT NOT NULL,
    token_type TEXT NOT NULL,
    parent_token_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_token_events_parent ON token_events(parent_token_id);

CREATE TABLE IF NOT EXISTS ssh_auth_events (
    event_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    src_ip TEXT NOT NULL,
    target_host TEXT NOT NULL,
    username TEXT NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssh_events_ts ON ssh_auth_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_ssh_events_src ON ssh_auth_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_ssh_events_user ON ssh_auth_events(username);

CREATE TABLE IF NOT EXISTS network_fingerprints (
    event_id TEXT PRIMARY KEY,
    measured_rtt_ms REAL NOT NULL,
    ttl INTEGER NOT NULL,
    ja3_hash TEXT NOT NULL,
    claimed_geo_distance_km REAL NOT NULL,
    expected_rtt_ms_for_distance REAL NOT NULL
);
"""


class Store:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def insert_auth_events(self, events: Iterable[AuthEvent]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO auth_events
               (event_id, user_id, timestamp, src_ip, device_fingerprint,
                user_agent, geo_country, geo_city, session_id, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (e.event_id, e.user_id, e.timestamp, e.src_ip, e.device_fingerprint,
                 e.user_agent, e.geo_country, e.geo_city, e.session_id, int(e.success))
                for e in events
            ],
        )
        self.conn.commit()

    def insert_badge_events(self, events: Iterable[BadgeEvent]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO badge_events
               (event_id, user_id, timestamp, reader_id, building, floor)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(e.event_id, e.user_id, e.timestamp, e.reader_id, e.building, e.floor) for e in events],
        )
        self.conn.commit()

    def insert_token_events(self, events: Iterable[TokenEvent]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO token_events
               (token_id, user_id, session_id, issued_at, issued_ip,
                issued_device, token_type, parent_token_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (e.token_id, e.user_id, e.session_id, e.issued_at, e.issued_ip,
                 e.issued_device, e.token_type, e.parent_token_id)
                for e in events
            ],
        )
        self.conn.commit()

    def insert_network_fingerprints(self, fps: Iterable[NetworkFingerprint]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO network_fingerprints
               (event_id, measured_rtt_ms, ttl, ja3_hash,
                claimed_geo_distance_km, expected_rtt_ms_for_distance)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [
                (f.event_id, f.measured_rtt_ms, f.ttl, f.ja3_hash,
                 f.claimed_geo_distance_km, f.expected_rtt_ms_for_distance)
                for f in fps
            ],
        )
        self.conn.commit()

    def insert_ssh_events(self, events: Iterable[SSHAuthEvent]) -> None:
        self.conn.executemany(
            """INSERT OR REPLACE INTO ssh_auth_events
               (event_id, timestamp, src_ip, target_host, username, success)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(e.event_id, e.timestamp, e.src_ip, e.target_host, e.username, int(e.success)) for e in events],
        )
        self.conn.commit()

    def all_ssh_events(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM ssh_auth_events ORDER BY timestamp").fetchall()

    def all_auth_events(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM auth_events ORDER BY timestamp").fetchall()

    def all_badge_events(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM badge_events ORDER BY timestamp").fetchall()

    def all_token_events(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM token_events ORDER BY issued_at").fetchall()

    def all_network_fingerprints(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM network_fingerprints").fetchall()
