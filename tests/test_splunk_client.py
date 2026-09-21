from ingestion.schema import AuthEvent
from ingestion.splunk_client import _to_dict
from ingestion.store import Store


def test_to_dict_handles_dataclass():
    e = AuthEvent(event_id="e1", user_id="u1", timestamp=1.0, src_ip="10.0.0.1",
                  device_fingerprint="d", user_agent="ua", geo_country="US", geo_city="c",
                  session_id="s1")
    d = _to_dict(e)
    assert d["event_id"] == "e1"
    assert d["user_id"] == "u1"


def test_to_dict_handles_sqlite_row(tmp_path):
    store = Store(db_path=tmp_path / "t.db")
    e = AuthEvent(event_id="e1", user_id="u1", timestamp=1.0, src_ip="10.0.0.1",
                  device_fingerprint="d", user_agent="ua", geo_country="US", geo_city="c",
                  session_id="s1")
    store.insert_auth_events([e])
    row = store.all_auth_events()[0]
    d = _to_dict(row)
    assert d["event_id"] == "e1"
    assert d["user_id"] == "u1"
    store.close()
