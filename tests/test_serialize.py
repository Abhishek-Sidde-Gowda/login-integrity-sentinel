import json

from fusion.risk_score import compute_host_risk, compute_identity_risk
from scenarios.generate import build_full_dataset
from web.serialize import serialize_risk


def test_identity_and_host_scores_are_json_serializable():
    data = build_full_dataset()
    identity_scores = compute_identity_risk(
        data["auth_events"], data["badge_events"], data["fingerprints"], data["token_events"]
    )
    host_scores = compute_host_risk(data["ssh_events"])

    assert identity_scores and host_scores
    for s in identity_scores:
        payload = serialize_risk(s, "identity_id")
        json.dumps(payload)  # raises if anything (set, tuple, inf) leaked through
        assert payload["identity_id"] == s.identity_id
        assert payload["num_signals_tripped"] == s.num_signals_tripped

    for s in host_scores:
        payload = serialize_risk(s, "host_id")
        json.dumps(payload)
        assert payload["host_id"] == s.host_id
