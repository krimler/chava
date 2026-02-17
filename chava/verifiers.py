import jsonpointer
from typing import Any, Callable, Dict, List, Tuple
from .core import ChavaObject, compute_evidence_hash
import re


class VerifierRegistry:
    """Maps obligation kinds to verifier functions."""

    def __init__(self):
        self._registry: Dict[str, Callable] = {}

    def register(self, kind: str, verifier_fn: Callable) -> None:
        """Register a verifier for an obligation kind."""
        self._registry[kind] = verifier_fn

    def get_verifier(self, kind: str) -> Callable:
        """Retrieve verifier for a kind."""
        if kind not in self._registry:
            raise KeyError(f"No verifier registered for kind: {kind}")
        return self._registry[kind]

    def list_kinds(self) -> List[str]:
        """List all registered kinds."""
        return list(self._registry.keys())


def sql_safe_verifier(value: str, scope: str) -> str:
    """
    Checks SQL for DROP TABLE, unbounded subqueries, etc.
    Returns: "accept" | "reject" | "conditional"
    """
    if value is None:
        return "reject"

    sql_lower = str(value).lower().strip()

    dangerous_patterns = [
        r'\bdrop\s+table\b',
        r'\btruncate\s+\w+\b',
        r'\balter\s+table\b',
        r'\bdelete\s+from\s+\w+\b',
        r'\bupdate\s+\w+\s+set\b.*\bwhere\b\s*$',
        r'\bexec\b',
        r'\bsp_.*\b',
        r'\binsert\s+into\s+\w+\s+values\b.*\bselect\b',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, sql_lower):
            return "reject"

    injection_patterns = [
        r"';\s*",
        r';\s*drop',
        r';\s*truncate',
        r';\s*alter',
        r'\bunion\s+select\b',
    ]

    for pattern in injection_patterns:
        if re.search(pattern, sql_lower):
            return "reject"

    return "accept"


def pii_clean_verifier(value: Any, scope: str) -> str:
    """
    Checks for phone numbers, emails, SSNs in scoped field.
    Returns: "accept" | "reject"
    """
    if value is None:
        return "accept"

    text = str(value)

    pii_patterns = [
        r'\b\d{3}-\d{3}-\d{4}\b',
        r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',
        r'\b\d{10}\b',
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        r'\b\d{3}-\d{2}-\d{4}\b',
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    ]

    for pattern in pii_patterns:
        if re.search(pattern, text):
            return "reject"

    return "accept"


def schema_validator(value: dict, scope: str) -> str:
    """
    Validates against a simple schema (required fields, types).
    Returns: "accept" | "reject"
    """
    if not isinstance(value, dict):
        return "reject"

    required_fields = {
        'id': int,
        'name': str
    }

    for field_name, expected_type in required_fields.items():
        if field_name not in value:
            return "reject"
        if not isinstance(value[field_name], expected_type):
            return "reject"

    return "accept"


def get_default_registry() -> VerifierRegistry:
    """Get a registry with default verifiers."""
    registry = VerifierRegistry()
    registry.register("sql_safe", sql_safe_verifier)
    registry.register("pii_clean", pii_clean_verifier)
    registry.register("schema_ok", schema_validator)
    return registry
