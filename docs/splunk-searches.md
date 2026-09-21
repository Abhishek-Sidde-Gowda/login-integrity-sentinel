# Splunk-side correlation searches

Three of the five signals map cleanly onto single-index SPL and are
saved as real, persisted searches in the live Splunk instance (not
just ad-hoc queries) - see `splunk/*.spl` for the queries themselves:

- `ssh_classic_brute_force.spl`
- `ssh_low_and_slow_password_spray.spl`
- `cross_account_credential_farm_burst.spl`

The other two signals - physical-logical fusion (a join between two
different sourcetypes with a staleness window and per-user bisection)
and session-token fork detection (a lineage graph over parent/child
token relationships) - stay in the Python fusion engine
(`detection/`, `fusion/`). Both are naturally graph/join operations
that Python expresses far more directly than SPL's `join`/`transaction`
commands would, and duplicating them in SPL would be worse code, not
more thorough coverage. Evasion fingerprinting also stays in Python
since it's a per-event computed-field comparison, not a correlation
across events - there's nothing for a saved search to aggregate.

## Verified live (2026-09-21)

Pushed the full synthetic dataset from the SQLite store to the real
Dockerized Splunk instance via `cli.py push-splunk`, confirmed indexed
counts matched, then created each search above as a real saved search
via the REST API and **dispatched them as saved-search jobs** (not
just ad-hoc SPL strings) to prove the persisted objects work:

| Saved search | Result |
|---|---|
| SSH Classic Brute Force | 1 row: `45.83.64.204` -> `web-edge-07`, 39 attempts - matches the Python detector exactly |
| SSH Low-and-Slow Password Spray | 2 rows (bucketed by 5h window) covering `app-db-03`, summing to the same 15 distinct sources the Python detector found |
| Cross-Account Credential Farm Burst | Every injected 25-account burst detected, one row per burst |

## Bug found and fixed: doubled `search` command

Creating a saved search via `POST .../saved/searches` with a `search`
field that itself starts with the word `search` (e.g. `search
index=login_integrity_ssh ...`) produces a dispatched job whose actual
query is `search search index=login_integrity_ssh ...` - Splunk's
dispatcher always prepends its own `search` command when running a
saved search, so including it yourself doubles it. The second `search`
token is then interpreted as a full-text keyword filter (search for
the literal word "search" in every event), which matched zero events
and silently returned an empty result set with no error - `isFailed:
false`, `scanCount: 0`, no messages. Caught by fetching the dispatched
job's actual recorded `search` field via
`/services/search/jobs/<sid>?output_mode=json` and comparing it to
what was intended, not by any error message (there wasn't one).

Fixed by storing the saved searches' `search` field starting directly
with `index=...` (no leading `search` keyword) - Splunk's own ad-hoc
`/services/search/jobs/export` endpoint (used by
`ingestion/splunk_client.py::run_search`) has no such quirk, since it
takes over prepending `search` only when the string doesn't already
start with a generating command, which is why the earlier ad-hoc test
of the identical query string worked while the saved-search version
silently didn't - the discrepancy was the tell that something in the
dispatch path specifically, not the query itself, was wrong.
