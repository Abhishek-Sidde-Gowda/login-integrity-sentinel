# Login Integrity Sentinel

Detects attacker-controlled "multiple logging in" activity - credential
farms, session/token theft, and physical-logical identity spoofing -
by fusing five signals almost nothing combines into one score, instead
of one more impossible-travel rule.

This is the 9th tool in a security portfolio. See the wider portfolio's
build order in the sibling tool READMEs (network-traffic-analyzer,
purple-team-platform, ai-soc-homelab, argus, iam-drift-sentinel).

## Why this exists

Standard SIEM content (including Splunk's own Security Essentials app)
already covers impossible travel, concurrent-session thresholds, and
per-IP brute-force counters well. Those are per-event or per-account
rules. The five signals here are deliberately population-level or
cross-signal instead:

1. **Cross-account login-timing correlation** - many *unrelated*
   accounts authenticating within a tight synchronized window, repeated
   over time. Invisible to per-account anomaly detection, since each
   individual login looks normal; visible only across the population.
2. **Physical-logical identity fusion** - a badge read places a user in
   one building; moments later a login originates from a network
   segment mapped to a different building. Physical presence can't be
   VPN-spoofed the way an IP can.
3. **Evasion-aware network fingerprinting** - claimed geolocation looks
   local, but measured RTT is far higher than physically plausible for
   that distance - consistent with a residential-proxy relay spoofing
   geolocation to defeat impossible-travel rules that trust geoIP alone.
4. **Session-token fork detection** - one OAuth refresh token spawning
   access tokens used from divergent device/IP pairs concurrently. A
   legitimate client's token lineage never forks this way.
5. **SSH low-and-slow password-spray detection** - many distinct source
   IPs, each trying a handful of common usernames a few times over
   hours, all against the same host. No single IP or account crosses a
   naive per-entity failure threshold; the signal only exists at the
   population level (unusual fan-out of `(src_ip, username)` pairs
   against one target in one window). A classic single-source brute
   force is included too, as the baseline case this is designed to beat.

## Honesty note on data sources

Signal 2's badge/RFID events are **explicitly synthetic**. This
portfolio's [rfid-usb-correlation-engine](../rfid-usb-correlation-engine)
tool has no hardware acquired yet and is still in planning status - this
tool does not claim a live physical-access integration it doesn't have.
Badge events are generated in `scenarios/generate.py` and labeled as
such throughout; the fusion logic is written so real reader hardware
could be dropped in later without changing anything downstream.

Splunk is a **real Splunk Enterprise instance**, not mocked - running
locally via the official `splunk/splunk` Docker image (trial license,
Splunk's General Terms accepted explicitly before first run) rather
than a manual splunk.com download. See `docs/splunk-docker.md` for the
container setup and `ingestion/splunk_client.py` / `.env.example` for
connection config. HEC ingestion -> Splunk indexing -> REST search
readback was confirmed working end to end against this instance on
2026-09-21. Phase 8 does the same live-verification pass once the
detection phases below exist to feed it.

## Status

- [x] **Phase 1 - Event schemas + SQLite mirror store + synthetic
      scenario generators.** `ingestion/schema.py` defines `AuthEvent`,
      `BadgeEvent`, `TokenEvent`, `NetworkFingerprint`, `SSHAuthEvent`.
      `ingestion/store.py` is a SQLite mirror the detection layer queries
      directly (same pattern as iam-drift-sentinel), independent of
      Splunk being up. `scenarios/generate.py` builds a normal
      population plus one injected attack pattern per signal above; all
      8 tests in `tests/test_store_and_scenarios.py` pass, and
      `python -m scenarios.run_scenarios` round-trips 500+ events through
      the real SQLite store end to end.
      `ingestion/splunk_client.py` (HEC ingestion + REST search) is
      **live-verified** against a real Dockerized Splunk Enterprise
      instance - see `docs/splunk-docker.md`.
- [ ] **Phase 2 - Cross-account timing correlation engine** (signal 1)
- [ ] **Phase 3 - Physical-logical fusion** (signal 2)
- [ ] **Phase 4 - Evasion-aware concurrency detector** (signal 3)
- [ ] **Phase 5 - Session-token fork detection** (signal 4, networkx lineage graph)
- [ ] **Phase 6 - SSH brute-force / low-and-slow spray detection** (signal 5)
- [ ] **Phase 7 - Fusion risk score** combining all five signals per identity/session
- [ ] **Phase 8 - CLI + Flask dashboard** (matches rest of portfolio)
- [ ] **Phase 9 - Live verification** against the real Splunk instance
- [ ] **Phase 10 - README/DEMO finalization**

## Layout

```
ingestion/    event schemas, SQLite store, Splunk HEC/REST client
detection/    per-signal detection logic (phases 2-6)
fusion/       combined risk scoring (phase 7)
cli/          command-line entry point
web/          Flask dashboard
scenarios/    synthetic normal population + attack-pattern generators
splunk/       saved searches / dashboard XML for the real Splunk instance
tests/
docs/
```

## Running Phase 1 so far

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m scenarios.run_scenarios   # builds + loads the synthetic dataset
```
