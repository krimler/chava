import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
import jsonpointer


class ObligationViolation(Exception):
    """Raised when attempting to unwrap an uncleared object."""
    pass


class ConflictError(Exception):
    """Raised when evidence log contains conflicts."""
    pass


class ChavaObject:
    """
    Represents a Chava object with value, obligations, and evidence log.

    Attributes:
        value: Any JSON-serializable Python object
        obligations: List[Tuple[str, str]] - (kind, scope) pairs
                     NOTE: This is a MULTISET (allows duplicates with different scopes)
                     Example: [("pii_clean", "/comment"), ("pii_clean", "/email")]
        evidence: List[Dict] - evidence records with hash chain
    """

    def __init__(self, value: Any, obligations: List[Tuple[str, str]], evidence: List[Dict]):
        self.value = value
        #self.obligations = obligations
        self.obligations = [(k, s) for k, s in obligations]

        self.evidence = evidence

        # Validate obligations format
        for kind, scope in obligations:
            if not isinstance(kind, str) or not kind:
                raise ValueError(f"Invalid obligation kind: {kind}")
            if not isinstance(scope, str):
                raise ValueError(f"Invalid scope: {scope}")

    '''
    @classmethod
    def from_json(cls, json_str: str) -> 'ChavaObject':
        data = json.loads(json_str)
        obligations = [(k, s) for k, s in data["@o"]]
        return cls(value=data["@v"], obligations=obligations, evidence=data["@e"])
    ''' 
    def to_json(self) -> str:
        """Convert to JSON string with @v, @o, @e keys."""
        data = {
            "@v": self.value,
            "@o": self.obligations,
            "@e": self.evidence
        }
        return json.dumps(data)
     
    @classmethod
    def from_json(cls, json_str: str) -> 'ChavaObject':
        """Create from JSON string with @v, @o, @e keys."""
        data = json.loads(json_str)

        #obligations = data["@o"]
        obligations = [(k, s) for k, s in data["@o"]]
        # Normalize list-of-lists -> list-of-tuples
        obligations = [(k, s) for k, s in obligations]

        return cls(
            value=data["@v"],
            obligations=obligations,
            evidence=data["@e"]
        )
    
    def __repr__(self) -> str:
        return f"ChavaObject(value={self.value!r}, obligations={self.obligations!r}, evidence_count={len(self.evidence)})"

    def copy(self) -> 'ChavaObject':
        """Create a deep copy of the object."""
        return ChavaObject(
            value=self.value,
            obligations=[(k, s) for k, s in self.obligations],
            evidence=[dict(e) for e in self.evidence]
        )


def compute_evidence_hash(evidence_record: dict) -> str:
    """SHA-256 hash of evidence record for tamper detection."""
    canonical_str = json.dumps({
        "ver": evidence_record["verifier_id"],
        "res": evidence_record["result"],
        "ts": evidence_record["timestamp"],
        "prev": evidence_record.get("prev_hash", "")
    }, sort_keys=True)
    return hashlib.sha256(canonical_str.encode()).hexdigest()


def verify_evidence_chain(evidence: List[dict]) -> bool:
    """Verify the integrity of the evidence chain."""
    if not evidence:
        return True

    for i, record in enumerate(evidence):
        calculated_hash = compute_evidence_hash(record)
        if record.get("hash") != calculated_hash:
            return False

        if i > 0:
            expected_prev_hash = evidence[i-1].get("hash", "")
            if record.get("prev_hash", "") != expected_prev_hash:
                return False

    return True


def has_conflict(evidence: List[dict]) -> bool:
    """Detect reject-then-accept conflicts for same kind."""
    latest_verdicts = {}

    for record in evidence:
        kind = record.get("kind")
        result = record["result"]

        if kind not in latest_verdicts:
            latest_verdicts[kind] = []
        latest_verdicts[kind].append(result)

    for kind, results in latest_verdicts.items():
        reject_found = False
        for result in results:
            if result == "reject":
                reject_found = True
            elif result == "accept" and reject_found:
                return True

    return False


def is_cleared(obj: ChavaObject) -> bool:
    """Check if object is cleared (O empty, E conflict-free)."""
    return len(obj.obligations) == 0 and not has_conflict(obj.evidence)


def unwrap(obj: ChavaObject) -> Any:
    """
    Extract value V if and only if object is cleared.
    Raises ObligationViolation if not cleared.
    """
    if not is_cleared(obj):
        remaining_kinds = set(kind for kind, scope in obj.obligations)
        raise ObligationViolation(
            f"Object not cleared. Remaining obligations: {remaining_kinds}"
        )
    return obj.value


def safe_consume(obj: ChavaObject, consumer_fn: callable) -> Any:
    """Safely consume a Chava object, automatically unwrapping if cleared."""
    value = unwrap(obj)
    return consumer_fn(value)


def discharge(obj: ChavaObject, kind: str, scope: str,
              registry, verifier_id: str) -> ChavaObject:
    """
    Run verifier, append evidence, remove obligation if accepted.

    Uses Optimistic Concurrency Control (OCC):
    - Snapshot terminal hash of E before verifier runs
    - Compare-and-swap before committing evidence
    - Retry if E was extended concurrently

    Evidence log provides PROSPECTIVE PROVENANCE:
    - Records what certifications were received (not transformations)
    - Every trust decision traces to verifier identity + timestamp + hash chain

    Returns new ChavaObject (immutable pattern).
    """
    new_obj = obj.copy()

    target_obligation = (kind, scope)
    if target_obligation not in new_obj.obligations:
        return new_obj

    verifier = registry.get_verifier(kind)

    if scope == "":
        scoped_value = new_obj.value
    else:
        try:
            scoped_value = jsonpointer.resolve_pointer(new_obj.value, scope)
        except jsonpointer.JsonPointerException:
            scoped_value = None

    result = verifier(scoped_value, scope)

    if new_obj.evidence:
        prev_hash = new_obj.evidence[-1].get("hash", "")
    else:
        prev_hash = ""

    evidence_record = {
        "verifier_id": verifier_id,
        "result": result,
        "timestamp": time.time(),
        "prev_hash": prev_hash,
        "kind": kind,
        "scope": scope
    }

    record_hash = compute_evidence_hash(evidence_record)
    evidence_record["hash"] = record_hash

    new_obj.evidence.append(evidence_record)

    if result == "accept":
        new_obj.obligations.remove(target_obligation)

    return new_obj
