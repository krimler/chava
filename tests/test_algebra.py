from chava.core import ChavaObject
from chava.algebra import project, merge, relscope


def test_relscope_basic():
    assert relscope("/comment/text", "/comment") == "/text"
    assert relscope("/comment", "/comment") == ""
    assert relscope("", "/any/path") == ""
    assert relscope("/a/b/c", "/a") == "/b/c"


def test_project_preserves_scoped_obligation():
    obj = ChavaObject(
        value={"comment": "hello", "other": "data"},
        obligations=[("pii_clean", "/comment"), ("other_check", "/other")],
        evidence=[]
    )

    projected = project(obj, "/comment")
    assert projected.value == "hello"
    assert ("pii_clean", "") in projected.obligations
    assert not any(kind == "other_check" for kind, _ in projected.obligations)


def test_project_invalid_path():
    obj = ChavaObject(
        value={"comment": "hello"},
        obligations=[("pii_clean", "/comment")],
        evidence=[]
    )

    projected = project(obj, "/nonexistent")
    assert projected.value is None
    assert ("invalid_path", "") in projected.obligations


def test_merge_scope_rewriting():
    obj1 = ChavaObject(value={"field": "val1"}, obligations=[("pii_clean", "/field")], evidence=[])
    obj2 = ChavaObject(value={"field": "val2"}, obligations=[("sql_safe", "/field")], evidence=[])

    merged = merge(obj1, obj2)
    assert merged.value == [{"field": "val1"}, {"field": "val2"}]
    assert ("pii_clean", "/0/field") in merged.obligations
    assert ("sql_safe", "/1/field") in merged.obligations
