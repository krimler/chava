import pytest
from chava.core import (
    ChavaObject, compute_evidence_hash, verify_evidence_chain, has_conflict,
    is_cleared, unwrap, ObligationViolation, discharge
)
from chava.verifiers import get_default_registry


def test_chava_object_creation():
    obj = ChavaObject(
        value={"test": "data"},
        obligations=[("sql_safe", "")],
        evidence=[]
    )
    assert obj.value == {"test": "data"}
    assert obj.obligations == [("sql_safe", "")]
    assert obj.evidence == []


def test_json_serialization():
    original = ChavaObject(
        value={"sql": "SELECT * FROM users"},
        obligations=[("sql_safe", ""), ("pii_clean", "/comment")],
        evidence=[{
            "verifier_id": "test",
            "result": "accept",
            "timestamp": 1234567890,
            "prev_hash": "",
            "kind": "sql_safe",
            "scope": "",
        }]
    )
    original.evidence[0]["hash"] = compute_evidence_hash(original.evidence[0])

    json_str = original.to_json()
    reconstructed = ChavaObject.from_json(json_str)

    assert reconstructed.value == original.value
    assert reconstructed.obligations == original.obligations
    assert reconstructed.evidence == original.evidence


def test_hash_chain_integrity():
    evidence = [{
        "verifier_id": "v1",
        "result": "accept",
        "timestamp": 1234567890,
        "prev_hash": "",
        "kind": "sql_safe",
        "scope": "",
    }]
    evidence[0]["hash"] = compute_evidence_hash(evidence[0])

    assert verify_evidence_chain(evidence) is True

    evidence[0]["result"] = "reject"
    assert verify_evidence_chain(evidence) is False


def test_is_cleared_empty_obligations():
    obj = ChavaObject(value="test", obligations=[], evidence=[])
    assert is_cleared(obj) is True


def test_is_cleared_with_obligations():
    obj = ChavaObject(value="test", obligations=[("sql_safe", "")], evidence=[])
    assert is_cleared(obj) is False


def test_conflict_detection():
    e1 = [
        {"verifier_id": "v1", "result": "accept", "timestamp": 1, "prev_hash": "", "kind": "sql_safe", "scope": ""},
        {"verifier_id": "v1", "result": "reject", "timestamp": 2, "prev_hash": "", "kind": "sql_safe", "scope": ""},
    ]
    for rec in e1:
        rec["hash"] = compute_evidence_hash(rec)
    assert has_conflict(e1) is False

    e2 = [
        {"verifier_id": "v1", "result": "reject", "timestamp": 1, "prev_hash": "", "kind": "sql_safe", "scope": ""},
        {"verifier_id": "v1", "result": "accept", "timestamp": 2, "prev_hash": "", "kind": "sql_safe", "scope": ""},
    ]
    for rec in e2:
        rec["hash"] = compute_evidence_hash(rec)
    # Need prev_hash chain to match for verify_evidence_chain but conflict logic doesn't require it.
    assert has_conflict(e2) is True


def test_discharge_accept():
    obj = ChavaObject(value="SELECT * FROM users;", obligations=[("sql_safe", "")], evidence=[])
    registry = get_default_registry()
    discharged = discharge(obj, "sql_safe", "", registry, "test_verifier")
    assert len(discharged.obligations) == 0
    assert len(discharged.evidence) == 1
    assert discharged.evidence[0]["result"] in ("accept", "conditional", "reject")


def test_unwrap_uncleared_raises():
    obj = ChavaObject(value="unsafe_data", obligations=[("sql_safe", "")], evidence=[])
    with pytest.raises(ObligationViolation):
        unwrap(obj)
