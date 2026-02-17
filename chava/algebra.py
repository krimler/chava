import jsonpointer
from typing import List, Tuple
from .core import ChavaObject, ObligationViolation


def relscope(scope: str, path: str) -> str:
    """
    Reanchor scope relative to new root path.

    Examples:
      relscope("/comment/text", "/comment") -> "/text"
      relscope("/comment", "/comment") -> ""
      relscope("", any_path) -> ""
    """
    if scope == "":
        return ""

    scope = scope.lstrip('/')
    path = path.lstrip('/')

    if scope.startswith(path):
        remaining = scope[len(path):].lstrip('/')
        if remaining:
            return "/" + remaining
        else:
            return ""

    return ""


def project(obj: ChavaObject, path: str) -> ChavaObject:
    """
    Extract field at JSON Pointer path, preserving scoped obligations.

    Uses relscope operation: relscope(p/q, p) = /q
    If path doesn't exist, inject invalid_path obligation.
    """
    try:
        extracted_value = jsonpointer.resolve_pointer(obj.value, path)
    except jsonpointer.JsonPointerException:
        new_obligations = obj.obligations + [("invalid_path", "")]
        return ChavaObject(
            value=None,
            obligations=new_obligations,
            evidence=obj.evidence
        )

    new_obligations = []
    for kind, scope in obj.obligations:
        if scope == "" or scope == path or scope.startswith(path + "/"):
            new_scope = relscope(scope, path)
            new_obligations.append((kind, new_scope))
        elif path.startswith(scope + "/"):
            new_obligations.append((kind, ""))

    return ChavaObject(
        value=extracted_value,
        obligations=new_obligations,
        evidence=obj.evidence.copy()
    )


def merge(obj1: ChavaObject, obj2: ChavaObject) -> ChavaObject:
    """
    Merge two objects with AND-conjunction semantics.
    Result value is [V1, V2].
    """
    merged_value = [obj1.value, obj2.value]
    merged_obligations = []

    for kind, scope in obj1.obligations:
        new_scope = "/0" if scope == "" else "/0" + scope
        merged_obligations.append((kind, new_scope))

    for kind, scope in obj2.obligations:
        new_scope = "/1" if scope == "" else "/1" + scope
        merged_obligations.append((kind, new_scope))

    merged_evidence = obj1.evidence + obj2.evidence

    return ChavaObject(
        value=merged_value,
        obligations=merged_obligations,
        evidence=merged_evidence
    )
