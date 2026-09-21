"""Module-level Flask dashboard - matches the portfolio's house pattern
(module-level `app`, `/api/*` JSON endpoints, a single index.html
template that polls them). Reads from the SQLite store populated by
`cli.py load-scenarios` (or a real ingestion pipeline later) - it never
regenerates data itself, so the dashboard reflects whatever is
actually in the store.
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template

from fusion.risk_score import compute_host_risk, compute_identity_risk
from ingestion.store import Store
from web.serialize import serialize_risk

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/identity-risk")
def api_identity_risk():
    store = Store()
    scores = compute_identity_risk(
        store.all_auth_events(), store.all_badge_events(),
        store.all_network_fingerprints(), store.all_token_events(),
    )
    store.close()
    board = [serialize_risk(s, "identity_id") for s in scores]
    return jsonify({"identities": board, "total": len(board)})


@app.route("/api/host-risk")
def api_host_risk():
    store = Store()
    scores = compute_host_risk(store.all_ssh_events())
    store.close()
    board = [serialize_risk(s, "host_id") for s in scores]
    return jsonify({"hosts": board, "total": len(board)})


@app.route("/api/identity/<path:identity_id>")
def api_identity_detail(identity_id: str):
    store = Store()
    scores = compute_identity_risk(
        store.all_auth_events(), store.all_badge_events(),
        store.all_network_fingerprints(), store.all_token_events(),
    )
    store.close()
    match = next((s for s in scores if s.identity_id == identity_id), None)
    if match is None:
        return jsonify({"error": "identity not found or not currently scored"}), 404
    return jsonify(serialize_risk(match, "identity_id"))


@app.route("/api/host/<path:host_id>")
def api_host_detail(host_id: str):
    store = Store()
    scores = compute_host_risk(store.all_ssh_events())
    store.close()
    match = next((s for s in scores if s.host_id == host_id), None)
    if match is None:
        return jsonify({"error": "host not found or not currently scored"}), 404
    return jsonify(serialize_risk(match, "host_id"))


@app.route("/api/summary")
def api_summary():
    store = Store()
    counts = {
        "auth_events": len(store.all_auth_events()),
        "badge_events": len(store.all_badge_events()),
        "token_events": len(store.all_token_events()),
        "fingerprints": len(store.all_network_fingerprints()),
        "ssh_events": len(store.all_ssh_events()),
    }
    store.close()
    return jsonify(counts)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5220, debug=True)
