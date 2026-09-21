"""Build the synthetic dataset and load it into the local SQLite store.
Run: python -m scenarios.run_scenarios
"""
from __future__ import annotations

from ingestion.store import Store
from scenarios.generate import build_full_dataset


def main() -> None:
    data = build_full_dataset()
    store = Store()
    store.insert_auth_events(data["auth_events"])
    store.insert_badge_events(data["badge_events"])
    store.insert_token_events(data["token_events"])
    store.insert_network_fingerprints(data["fingerprints"])
    store.insert_ssh_events(data["ssh_events"])
    print(f"auth_events:        {len(data['auth_events'])}")
    print(f"badge_events:       {len(data['badge_events'])}")
    print(f"token_events:       {len(data['token_events'])}")
    print(f"fingerprints:       {len(data['fingerprints'])}")
    print(f"ssh_events:         {len(data['ssh_events'])}")
    print(f"-> {store.db_path}")
    store.close()


if __name__ == "__main__":
    main()
