#!/usr/bin/env python3
"""Login Integrity Sentinel - argparse CLI, matching the portfolio's
house style (argparse + module-level Flask, see iam-drift-sentinel/cli.py)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ingestion.store import DEFAULT_DB_PATH, Store


def c(text: str, color: str) -> str:
    codes = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "bold": "1"}
    return f"\033[{codes[color]}m{text}\033[0m"


def print_section(title: str) -> None:
    print(f"\n{c(title, 'bold')}")
    print(c("-" * len(title), "cyan"))


def cmd_load_scenarios(args: argparse.Namespace) -> int:
    from scenarios.generate import build_full_dataset

    store = Store(args.db or DEFAULT_DB_PATH)
    data = build_full_dataset()
    store.insert_auth_events(data["auth_events"])
    store.insert_badge_events(data["badge_events"])
    store.insert_token_events(data["token_events"])
    store.insert_network_fingerprints(data["fingerprints"])
    store.insert_ssh_events(data["ssh_events"])

    print_section("Loaded synthetic dataset")
    print(f"  auth_events:  {len(data['auth_events'])}")
    print(f"  badge_events: {len(data['badge_events'])}")
    print(f"  token_events: {len(data['token_events'])}")
    print(f"  fingerprints: {len(data['fingerprints'])}")
    print(f"  ssh_events:   {len(data['ssh_events'])}")
    print(c(f"-> {store.db_path}", "green"))
    store.close()
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    from fusion.risk_score import compute_host_risk, compute_identity_risk

    store = Store(args.db or DEFAULT_DB_PATH)
    identity_scores = compute_identity_risk(
        store.all_auth_events(), store.all_badge_events(),
        store.all_network_fingerprints(), store.all_token_events(),
    )
    host_scores = compute_host_risk(store.all_ssh_events())
    store.close()

    if not identity_scores and not host_scores:
        print(c("No risk found - store may be empty. Run `load-scenarios` first.", "yellow"))
        return 1

    print_section("Login Integrity Sentinel - identity risk")
    for s in identity_scores[:25]:
        print(f"  {s.identity_id:<20} total={s.total_score:8.1f}  signals={','.join(s.signal_scores)}")

    print_section("Login Integrity Sentinel - host risk")
    for s in host_scores:
        print(f"  {s.host_id:<20} total={s.total_score:8.1f}  signals={','.join(s.signal_scores)}")
    return 0


def cmd_push_splunk(args: argparse.Namespace) -> int:
    from ingestion.splunk_client import SplunkClient, SplunkConfigError

    store = Store(args.db or DEFAULT_DB_PATH)
    client = SplunkClient()
    try:
        client.send_auth_events(store.all_auth_events())
        client.send_badge_events(store.all_badge_events())
        client.send_token_events(store.all_token_events())
        client.send_network_fingerprints(store.all_network_fingerprints())
        client.send_ssh_events(store.all_ssh_events())
    except SplunkConfigError as exc:
        print(c(f"Splunk not configured: {exc}", "red"))
        store.close()
        return 1
    print(c("Pushed all stored events to Splunk over HEC.", "green"))
    store.close()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from web.app import app
    app.run(host="127.0.0.1", port=args.port, debug=args.debug)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Login Integrity Sentinel")
    sub = parser.add_subparsers(dest="command", required=True)

    load_parser = sub.add_parser("load-scenarios", help="Build and load the synthetic dataset into the store")
    load_parser.add_argument("--db", type=Path, default=None, help=f"SQLite store path (default: {DEFAULT_DB_PATH})")
    load_parser.set_defaults(func=cmd_load_scenarios)

    score_parser = sub.add_parser("score", help="Print the fused identity/host risk board")
    score_parser.add_argument("--db", type=Path, default=None, help=f"SQLite store path (default: {DEFAULT_DB_PATH})")
    score_parser.set_defaults(func=cmd_score)

    push_parser = sub.add_parser("push-splunk", help="Push everything currently in the store to Splunk over HEC")
    push_parser.add_argument("--db", type=Path, default=None, help=f"SQLite store path (default: {DEFAULT_DB_PATH})")
    push_parser.set_defaults(func=cmd_push_splunk)

    serve_parser = sub.add_parser("serve", help="Launch the web dashboard")
    serve_parser.add_argument("--port", type=int, default=5220)
    serve_parser.add_argument("--debug", action="store_true")
    serve_parser.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
