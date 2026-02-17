from chava.indexes import InvertedObligationIndex, HierarchicalPointerIndex, EvidenceLogIndex


def test_inverted_index_lookup():
    index = InvertedObligationIndex()
    index.add("obj1", [("sql_safe", ""), ("pii_clean", "/comment")])
    index.add("obj2", [("sql_safe", "")])
    index.add("obj3", [("schema_ok", "")])

    sql_safe_objects = index.get_objects_with_kind("sql_safe")
    assert "obj1" in sql_safe_objects
    assert "obj2" in sql_safe_objects
    assert "obj3" not in sql_safe_objects


def test_hierarchical_index_trie():
    index = HierarchicalPointerIndex()
    index.add("obj1", [("pii_clean", "/user/comment")])
    index.add("obj2", [("pii_clean", "/user/profile/email")])
    index.add("obj3", [("sql_safe", "/query")])

    user_objects = index.get_objects_at_path("/user")
    assert "obj1" in user_objects
    assert "obj2" in user_objects
    assert "obj3" not in user_objects

    profile_objects = index.get_objects_at_path("/user/profile")
    assert "obj2" in profile_objects
    assert "obj1" not in profile_objects


def test_evidence_index_query():
    index = EvidenceLogIndex()

    evidence_records = [
        {"verifier_id": "sql_verifier", "timestamp": 100, "result": "accept", "other": "data1"},
        {"verifier_id": "pii_verifier", "timestamp": 150, "result": "reject", "other": "data2"},
        {"verifier_id": "sql_verifier", "timestamp": 200, "result": "accept", "other": "data3"},
        {"verifier_id": "schema_verifier", "timestamp": 180, "result": "reject", "other": "data4"}
    ]

    index.add("obj1", [evidence_records[0]])
    index.add("obj2", [evidence_records[1]])
    index.add("obj3", [evidence_records[2]])
    index.add("obj4", [evidence_records[3]])

    sql_results = index.query_by_verifier("sql_verifier")
    assert len(sql_results) == 2

    time_results = index.query_by_time_range(120, 190)
    obj_ids = [obj_id for obj_id, _ in time_results]
    assert "obj2" in obj_ids
    assert "obj4" in obj_ids
    assert "obj1" not in obj_ids
    assert "obj3" not in obj_ids
