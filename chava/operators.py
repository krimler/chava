from typing import List
from .core import ChavaObject, is_cleared


def filter_cleared(objects: List[ChavaObject]) -> List[ChavaObject]:
    """σ_cleared operator: pass only cleared objects"""
    return [obj for obj in objects if is_cleared(obj)]


def inject_verification(objects: List[ChavaObject], kind: str,
                       registry, verifier_id: str) -> List[ChavaObject]:
    """
    V̂_k operator: run verifier on all objects.
    Objects without obligation k pass through unchanged.
    """
    from .core import discharge

    results = []
    for obj in objects:
        has_kind = any(k == kind for k, _ in obj.obligations)
        if has_kind:
            discharged_obj = discharge(obj, kind, "", registry, verifier_id)
            results.append(discharged_obj)
        else:
            results.append(obj)

    return results
