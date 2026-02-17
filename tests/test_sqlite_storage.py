import tempfile
import os
from chava.sqlite_storage import ChavaSQLiteStorage
from chava.kms import KeyManagementService
from chava.core import ChavaObject
from chava.verifiers import get_default_registry


def test_sqlite_store_and_retrieve():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms = KeyManagementService(b"test_secret")
            storage = ChavaSQLiteStorage(tmp_file.name, kms)

            obj = ChavaObject(value={"test": "data"}, obligations=[], evidence=[])
            storage.store("test_obj", obj)
            retrieved = storage.retrieve("test_obj")

            assert retrieved.value == {"test": "data"}
            assert retrieved.obligations == []
        finally:
            os.unlink(tmp_file.name)


def test_sqlite_survives_restart():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms1 = KeyManagementService(b"test_secret")
            storage1 = ChavaSQLiteStorage(tmp_file.name, kms1)

            obj = ChavaObject(value="persistent_data", obligations=[], evidence=[])
            storage1.store("persist_obj", obj)
            del storage1

            kms2 = KeyManagementService(b"test_secret")
            storage2 = ChavaSQLiteStorage(tmp_file.name, kms2)

            retrieved = storage2.retrieve("persist_obj")
            assert retrieved.value == "persistent_data"
        finally:
            os.unlink(tmp_file.name)


def test_sqlite_obligation_index_query():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms = KeyManagementService(b"test_secret")
            storage = ChavaSQLiteStorage(tmp_file.name, kms)

            obj1 = ChavaObject(value="sql_data", obligations=[("sql_safe", "")], evidence=[])
            obj2 = ChavaObject(value="pii_data", obligations=[("pii_clean", "")], evidence=[])
            obj3 = ChavaObject(value="both_data", obligations=[("sql_safe", ""), ("pii_clean", "")], evidence=[])

            storage.store("obj1", obj1)
            storage.store("obj2", obj2)
            storage.store("obj3", obj3)

            sql_safe_ids = storage.query_by_obligation("sql_safe")
            assert "obj1" in sql_safe_ids
            assert "obj3" in sql_safe_ids
            assert "obj2" not in sql_safe_ids
        finally:
            os.unlink(tmp_file.name)


def test_sqlite_batch_discharge():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms = KeyManagementService(b"test_secret")
            storage = ChavaSQLiteStorage(tmp_file.name, kms)
            registry = get_default_registry()

            for i in range(3):
                obj = ChavaObject(value=f"SELECT * FROM t{i};", obligations=[("sql_safe", "")], evidence=[])
                storage.store(f"obj_{i}", obj)

            results = storage.batch_discharge(["obj_0", "obj_1", "obj_2"], "sql_safe", registry, "batch_verifier")
            assert all(results.values())

            for i in range(3):
                obj = storage.retrieve(f"obj_{i}")
                # depending on verifier, could be accept/conditional; accept removes obligation
                # We just assert evidence exists
                assert len(obj.evidence) >= 1
        finally:
            os.unlink(tmp_file.name)
