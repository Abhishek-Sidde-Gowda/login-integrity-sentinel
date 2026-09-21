"""Signal 4: session-token fork detection.

A legitimate OAuth client's token lineage is a simple chain: one
refresh token exchanged for one or more access tokens, all from the
same device/IP over the life of that session. A "fork" - the same
refresh token producing child tokens from two DIVERGENT device/IP
pairs close together in time - means the refresh token is being used
by two different clients at once, the signature of a stolen refresh
token being replayed by an attacker alongside the legitimate user.

Out-degree alone isn't the signal: a client can legitimately mint
several access tokens off one refresh token from the same device.
Divergent device/IP among children issued close together in time is.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from detection._util import as_dict

# Children issued within this window of each other are treated as one
# "burst" of refresh activity. A legitimate client re-authenticating
# from a new device a week later isn't a fork; two clients using the
# same refresh token seconds apart is.
FORK_WINDOW_SECONDS = 60.0

_TOKEN_FIELDS = ("token_id", "user_id", "session_id", "issued_at",
                  "issued_ip", "issued_device", "token_type", "parent_token_id")


@dataclass
class TokenForkFinding:
    parent_token_id: str
    user_id: str
    child_token_ids: list[str] = field(default_factory=list)
    device_ip_pairs: set[tuple[str, str]] = field(default_factory=set)
    time_span_seconds: float = 0.0

    @property
    def risk_score(self) -> float:
        return len(self.device_ip_pairs) * 60.0 / max(self.time_span_seconds, 1.0)


def build_lineage_graph(token_events) -> nx.DiGraph:
    g = nx.DiGraph()
    for t in token_events:
        td = as_dict(t, _TOKEN_FIELDS)
        g.add_node(td["token_id"], **td)
        if td["parent_token_id"]:
            g.add_edge(td["parent_token_id"], td["token_id"])
    return g


def detect_forks(token_events, window_seconds: float = FORK_WINDOW_SECONDS) -> list[TokenForkFinding]:
    g = build_lineage_graph(token_events)
    findings = []

    for node in g.nodes:
        children = [g.nodes[c] for c in g.successors(node)]
        if len(children) < 2:
            continue
        children.sort(key=lambda d: d["issued_at"])

        divergent_pairs: set[tuple[str, str]] = set()
        window_min_ts = window_max_ts = None
        for i in range(len(children)):
            for j in range(i + 1, len(children)):
                a, b = children[i], children[j]
                if abs(a["issued_at"] - b["issued_at"]) > window_seconds:
                    continue
                pair_a, pair_b = (a["issued_ip"], a["issued_device"]), (b["issued_ip"], b["issued_device"])
                if pair_a == pair_b:
                    continue
                divergent_pairs.update((pair_a, pair_b))
                lo, hi = sorted((a["issued_at"], b["issued_at"]))
                window_min_ts = lo if window_min_ts is None else min(window_min_ts, lo)
                window_max_ts = hi if window_max_ts is None else max(window_max_ts, hi)

        if len(divergent_pairs) < 2:
            continue

        parent = g.nodes[node] if g.nodes[node] else {}
        findings.append(TokenForkFinding(
            parent_token_id=node,
            user_id=parent.get("user_id", children[0]["user_id"]),
            child_token_ids=[c["token_id"] for c in children],
            device_ip_pairs=divergent_pairs,
            time_span_seconds=(window_max_ts - window_min_ts) if window_max_ts is not None else 0.0,
        ))

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
