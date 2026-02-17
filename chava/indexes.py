from typing import List, Tuple, Dict, Set, Optional
from collections import defaultdict
import bisect


class InvertedObligationIndex:
    """Maps obligation kind -> list of object IDs"""

    def __init__(self):
        self.index: Dict[str, Set[str]] = defaultdict(set)

    def add(self, obj_id: str, obligations: List[Tuple[str, str]]) -> None:
        for kind, scope in obligations:
            self.index[kind].add(obj_id)

    def get_objects_with_kind(self, kind: str) -> List[str]:
        return list(self.index.get(kind, set()))

    def remove_obligation(self, obj_id: str, kind: str, scope: str) -> None:
        if kind in self.index and obj_id in self.index[kind]:
            self.index[kind].remove(obj_id)
            if not self.index[kind]:
                del self.index[kind]


class HierarchicalPointerIndex:
    """
    Trie over JSON Pointer path prefixes.
    Each node holds objects with obligations scoped at/below that path.
    """

    class TrieNode:
        def __init__(self):
            self.children = {}
            self.object_ids = set()

    def __init__(self):
        self.root = self.TrieNode()

    def _split_path(self, path: str) -> List[str]:
        if path == "":
            return []
        path = path.lstrip('/')
        if not path:
            return []
        return path.split('/')

    def add(self, obj_id: str, obligations: List[Tuple[str, str]]) -> None:
        for kind, scope in obligations:
            if scope == "":
                self.root.object_ids.add(obj_id)
            else:
                components = self._split_path(scope)
                node = self.root
                for comp in components:
                    if comp not in node.children:
                        node.children[comp] = self.TrieNode()
                    node = node.children[comp]
                node.object_ids.add(obj_id)

    def get_objects_at_path(self, path: str) -> Set[str]:
        components = self._split_path(path)
        node = self.root

        for comp in components:
            if comp in node.children:
                node = node.children[comp]
            else:
                break

        result = set(node.object_ids)

        stack = [node]
        while stack:
            current_node = stack.pop()
            result.update(current_node.object_ids)
            stack.extend(current_node.children.values())

        return result

    def remove_obligation(self, obj_id: str, scope: str) -> None:
        if scope == "":
            self.root.object_ids.discard(obj_id)
        else:
            components = self._split_path(scope)
            self._remove_from_path(obj_id, components, self.root)

    def _remove_from_path(self, obj_id: str, components: List[str], node):
        if not components:
            node.object_ids.discard(obj_id)
            return

        comp = components[0]
        if comp in node.children:
            child_node = node.children[comp]
            self._remove_from_path(obj_id, components[1:], child_node)

            if not child_node.object_ids and not child_node.children:
                del node.children[comp]


class EvidenceLogIndex:
    """Index structure for querying evidence logs efficiently."""

    def __init__(self):
        self.verifier_index: Dict[str, List[Tuple[str, Dict]]] = defaultdict(list)
        self.timestamp_index: List[Tuple[float, str, Dict]] = []

    def add(self, obj_id: str, evidence: List[Dict]) -> None:
        for record in evidence:
            verifier_id = record["verifier_id"]
            self.verifier_index[verifier_id].append((obj_id, record))

            timestamp = record["timestamp"]
            self.timestamp_index.append((timestamp, obj_id, record))

        self.timestamp_index.sort(key=lambda x: x[0])

    def query_by_verifier(self, verifier_id: str) -> List[Tuple[str, Dict]]:
        return self.verifier_index.get(verifier_id, [])

    def query_by_time_range(self, start_time: float, end_time: float) -> List[Tuple[str, Dict]]:
        start_idx = bisect.bisect_left(self.timestamp_index, (start_time, "", {}))
        end_idx = bisect.bisect_right(self.timestamp_index, (end_time, "~", {}))
        return [(obj_id, record) for _, obj_id, record in self.timestamp_index[start_idx:end_idx]]
