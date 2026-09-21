# Demo script

A practical order to show this project live, cheapest and fastest first.
Every command below was actually run against this build before being
written down here - see the phase log in [README.md](README.md) for
what was found and fixed along the way at each step.

## Before you start

```bash
cd login-integrity-sentinel
python3 -m venv .venv && source .venv/bin/activate   # first time only
pip install -r requirements.txt                        # first time only
python cli.py load-scenarios
```

Builds a normal population plus one injected attack pattern per signal
(clearly-labeled synthetic data - see the README's honesty note on
`BadgeEvent`) and loads ~525 auth events, 370 badge reads, 745 token
events, 370 network fingerprints, and 73 SSH events into the local
SQLite store.

## 1. Dashboard (visual, free, instant)

```bash
python cli.py serve
```

Open `http://localhost:5220`. The identity and host risk boards are
reading live from the store populated above - click any row to open
its evidence detail panel and see the actual finding data (burst
membership, RTT ratios, token lineage, etc.), not placeholder text.

## 2. Terminal risk board (free, instant)

```bash
python cli.py score
```

Same fused risk scores as the dashboard, for a quick terminal-only
walkthrough: the 25 `farmvictim*` identities at `total=418.3` (recurring
cross-account timing bursts), then the evasion-fingerprint, token-fork,
and physical-logical identities further down, then the two SSH hosts.

## 3. Real Splunk (the "not a toy" moment)

```bash
docker start login-integrity-splunk   # if not already running - see docs/splunk-docker.md
python cli.py push-splunk
```

This sends everything currently in the store to a real, locally-running
Splunk Enterprise instance over HEC - not a mock. Open
`https://localhost:8000` (accept the self-signed cert warning), log in
with the admin credentials in `.splunk_docker.env`, and either:

- open **Search & Reporting -> Searches, Reports, and Alerts** and run
  any of the three "Login Integrity - ..." saved searches, or
- paste any query from `splunk/*.spl` directly into the search bar.

Each one reproduces exactly what the Python detectors found - see
`docs/splunk-searches.md` for the verified results table and a real
Splunk REST API gotcha (a doubled `search` command) caught while
building these.

## If there's no Docker/Splunk access at demo time

Steps 1-2 need only Python - no Docker, no external services. They
demonstrate the full fused five-signal pipeline end to end already;
Splunk in step 3 is corroborating evidence that three of the five
signals also work as real Splunk correlation searches, not the only
place the detection logic lives.
