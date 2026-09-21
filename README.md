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
- [x] **Phase 2 - Cross-account timing correlation engine** (signal 1).
      `detection/timing_correlation.py` - O(n) two-pointer sliding
      window finds bursts of anomalous distinct-user counts, scores
      against a cold baseline (windows outside every detected burst),
      flags recurring bursts (Jaccard >= 0.5 user-set overlap) as
      higher risk. **Bug found and fixed**: an initial leave-one-out
      baseline only excluded each burst's own windows, so a second
      recurring burst stayed in the first burst's baseline and damped
      its z-score (1.88 instead of >200) - fixed with one shared cold
      baseline excluding every detected burst, not per-burst
      leave-one-out. 12/12 tests passing; detected all 6 injected farm
      bursts in the full mixed dataset with zero false positives.
- [x] **Phase 3 - Physical-logical fusion** (signal 2).
      `detection/physical_logical_fusion.py` - bisects each user's
      sorted badge history to find the most recent read before a
      login, flags a mismatch when that badge's building differs from
      the login's network-segment building. Badge reads older than 4
      hours make no claim about current location and are excluded, as
      are logins from IPs outside any known building segment (no
      physical claim to contradict). Building<->network-segment
      mapping moved to `ingestion/network_topology.py` so the detector
      and the synthetic generator share one definition. 18/18 tests
      passing; detected exactly the 5 injected mismatches in the full
      mixed dataset with zero false positives.
- [x] **Phase 4 - Evasion-aware network fingerprinting** (signal 3).
      `detection/evasion_fingerprint.py` - flags logins whose measured
      RTT is far beyond the physical floor for the claimed geolocation
      distance (ratio >= 5x), catching residential-proxy relays that
      spoof geolocation to defeat geoIP-only impossible-travel checks.
      TTL/hop-count is a weak corroborating signal only, boosting risk
      score rather than gating detection alone. Threshold chosen with
      margin above the synthetic normal population's natural ceiling
      (max ratio 3.0). 23/23 tests passing; detected exactly the 5
      injected proxy cases in the full mixed dataset with zero false
      positives.
- [x] **Phase 5 - Session-token fork detection** (signal 4).
      `detection/token_fork.py` - builds a networkx DiGraph of token
      issuance lineage (`parent_token_id -> token_id`) and flags a
      refresh token whose children were issued from two or more
      divergent `(device, ip)` pairs within a 60-second window - the
      signature of a stolen refresh token replayed by an attacker
      alongside the legitimate user. Out-degree alone isn't the
      signal - a client legitimately minting several access tokens off
      one refresh token from the same device is not flagged, only
      divergence in who's using it. 28/28 tests passing; detected
      exactly the 5 injected forks in the full mixed dataset with zero
      false positives.
- [x] **Phase 6 - SSH brute-force / low-and-slow spray detection**
      (signal 5). `detection/ssh_bruteforce.py` - two detectors:
      `detect_brute_force()` (per-(host, src_ip) failure count over a
      sliding window) and `detect_password_spray()` (population-level
      fan-out of distinct source IPs against one host, each
      individually under the brute-force threshold - the pattern no
      per-entity rule can see by construction). A source already
      caught by the brute-force threshold is excluded from spray
      scoring so a loud single-source attack isn't double-counted.
      32/32 tests passing; detected exactly the injected 39-attempt
      brute force and 15-source spray in the full mixed dataset, each
      attributed to only its own detector, zero false positives.
- [x] **Phase 7 - Fusion risk score**. `fusion/risk_score.py` combines
      the four identity-keyed signals into one `IdentityRiskScore` per
      `user_id`, and the SSH signals into a separate `HostRiskScore`
      per `target_host` - kept separate deliberately, since SSH
      usernames here (root, admin, deploy) are shared infrastructure
      accounts, not durable per-person identities the way `user_id`
      is; joining them would be a fabricated correlation. Tripping
      multiple signals scores multiplicatively higher than the sum of
      its parts (1.5x per extra signal), mirroring iam-drift-
      sentinel's drift+behavior fusion. Every signal contribution is
      clamped to a finite cap before summing, since
      `timing_correlation`'s z-score can legitimately be +inf.
      39/39 tests passing; full mixed-dataset run produces 40 scored
      identities and 2 scored hosts, correctly sorted.
- [x] **Phase 8 - CLI + Flask dashboard** (matches rest of portfolio).
      `cli.py`: `load-scenarios`, `score`, `push-splunk`, `serve`
      (port 5220, registered in the root `.claude/launch.json`).
      `web/app.py` + `web/serialize.py` + `web/templates/index.html`:
      dark-theme dashboard (matching iam-drift-sentinel's style) with
      stat cards, identity/host risk boards, and a click-through
      evidence detail panel. **Bug found and fixed**: `SplunkClient`
      used `dataclasses.asdict()` directly, which raises on the
      `sqlite3.Row` objects `Store` returns - `push-splunk` would have
      crashed on first real use; fixed with a dataclass-or-Row-aware
      `_to_dict()`. Verified live in-browser: all `/api/*` endpoints
      return 200, both risk boards render with correct scores/badges,
      clicking a row opens the right evidence detail, no console
      errors. 42/42 tests passing.
- [x] **Phase 9 - Live verification** against the real Splunk instance.
      Pushed the full synthetic dataset to Splunk over HEC via `cli.py
      push-splunk`, confirmed indexed counts matched. Three of the five
      signals (SSH brute force, SSH password spray, cross-account
      timing) map cleanly onto single-index SPL and are saved as real
      Splunk searches (see `splunk/*.spl`, `docs/splunk-searches.md`) -
      dispatched as actual saved-search jobs (not ad-hoc queries) and
      confirmed they return the same findings as the Python detectors.
      The other two signals (physical-logical fusion, token forks) stay
      in the Python fusion engine, since they're joins/lineage graphs
      that Python expresses more directly than SPL's join/transaction
      commands. **Bug found and fixed**: a saved search whose `search`
      field itself starts with the word "search" gets double-prepended
      by Splunk's dispatcher, silently matching zero events with no
      error - caught by comparing the dispatched job's actual recorded
      query against what was intended, not by any error message.
- [ ] **Phase 10 - README/DEMO finalization**

## Layout

```
ingestion/    event schemas, SQLite store, Splunk HEC/REST client
detection/    per-signal detection logic (phases 2-6)
fusion/       combined risk scoring (phase 7)
cli/          command-line entry point
web/          Flask dashboard
scenarios/    synthetic normal population + attack-pattern generators
splunk/       saved SPL searches, mirrored into the real Splunk instance (see docs/splunk-searches.md)
tests/
docs/
```

## Running what's built so far

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m scenarios.run_scenarios   # builds + loads the synthetic dataset
```
