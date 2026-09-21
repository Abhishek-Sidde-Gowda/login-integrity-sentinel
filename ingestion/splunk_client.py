"""Thin client for a real Splunk Enterprise instance: HEC ingestion +
REST search. Config comes entirely from environment variables so no
Splunk credentials ever land in source control.

NOT YET LIVE-VERIFIED - Splunk isn't installed yet. This is the wiring
Phase 8 will exercise end-to-end against a real instance; until then,
treat every method here as unverified against real Splunk behavior.
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict
from typing import Any, Iterable

import requests

from ingestion.schema import AuthEvent, BadgeEvent, NetworkFingerprint, SSHAuthEvent, TokenEvent


class SplunkConfigError(RuntimeError):
    pass


class SplunkClient:
    def __init__(
        self,
        hec_url: str | None = None,
        hec_token: str | None = None,
        mgmt_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = False,
    ):
        self.hec_url = hec_url or os.environ.get("SPLUNK_HEC_URL")
        self.hec_token = hec_token or os.environ.get("SPLUNK_HEC_TOKEN")
        self.mgmt_url = mgmt_url or os.environ.get("SPLUNK_MGMT_URL", "https://localhost:8089")
        self.username = username or os.environ.get("SPLUNK_USER")
        self.password = password or os.environ.get("SPLUNK_PASSWORD")
        self.verify_tls = verify_tls

    def _require_hec(self) -> None:
        if not self.hec_url or not self.hec_token:
            raise SplunkConfigError(
                "SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set (see .env.example)"
            )

    def _send_hec(self, index: str, sourcetype: str, events: Iterable[dict[str, Any]]) -> None:
        self._require_hec()
        headers = {"Authorization": f"Splunk {self.hec_token}"}
        payload = "\n".join(
            self._hec_wrap(index, sourcetype, event) for event in events
        )
        if not payload:
            return
        resp = requests.post(self.hec_url, headers=headers, data=payload, verify=self.verify_tls, timeout=30)
        resp.raise_for_status()

    @staticmethod
    def _hec_wrap(index: str, sourcetype: str, event: dict[str, Any]) -> str:
        import json

        return json.dumps({
            "index": index,
            "sourcetype": sourcetype,
            "time": event.get("timestamp") or event.get("issued_at") or time.time(),
            "event": event,
        })

    def send_auth_events(self, events: Iterable[AuthEvent]) -> None:
        self._send_hec("login_integrity_auth", "auth_event", (asdict(e) for e in events))

    def send_badge_events(self, events: Iterable[BadgeEvent]) -> None:
        self._send_hec("login_integrity_badge", "badge_event", (asdict(e) for e in events))

    def send_token_events(self, events: Iterable[TokenEvent]) -> None:
        self._send_hec("login_integrity_token", "token_event", (asdict(e) for e in events))

    def send_ssh_events(self, events: Iterable[SSHAuthEvent]) -> None:
        self._send_hec("login_integrity_ssh", "ssh_auth_event", (asdict(e) for e in events))

    def send_network_fingerprints(self, fps: Iterable[NetworkFingerprint]) -> None:
        self._send_hec("login_integrity_netfp", "network_fingerprint", (asdict(f) for f in fps))

    def run_search(self, spl: str) -> list[dict[str, Any]]:
        """Run a oneshot SPL search via the REST API and return result rows."""
        if not self.username or not self.password:
            raise SplunkConfigError("SPLUNK_USER and SPLUNK_PASSWORD must be set to run searches")
        search = spl if spl.strip().startswith("search") else f"search {spl}"
        resp = requests.post(
            f"{self.mgmt_url}/services/search/jobs/export",
            auth=(self.username, self.password),
            data={"search": search, "output_mode": "json", "exec_mode": "oneshot"},
            verify=self.verify_tls,
            timeout=60,
        )
        resp.raise_for_status()
        rows = []
        for line in resp.text.splitlines():
            if not line.strip():
                continue
            import json

            rows.append(json.loads(line).get("result", {}))
        return rows
