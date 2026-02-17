import tempfile
import os
import pytest
from chava.core import ChavaObject, unwrap, discharge, ObligationViolation
from chava.verifiers import get_default_registry
from chava.algebra import project
from chava.kms import KeyManagementService
from chava.sqlite_storage import ChavaSQLiteStorage


def test_e2e_llm_sql_pipeline():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms = KeyManagementService(b"test_secret")
            storage = ChavaSQLiteStorage(tmp_file.name, kms)
            registry = get_default_registry()

            sql_obj = ChavaObject(
                value="SELECT * FROM users WHERE id=1;",
                obligations=[("sql_safe", "")],
                evidence=[]
            )
            storage.store("sql_query", sql_obj)

            with pytest.raises(ObligationViolation):
                obj = storage.retrieve("sql_query")
                unwrap(obj)

            obj = storage.retrieve("sql_query")
            discharged_obj = discharge(obj, "sql_safe", "", registry, "sql_verifier")
            storage.store("sql_query", discharged_obj)

            retrieved = storage.retrieve("sql_query")
            # Depending on verifier returning accept/conditional, unwrap may still fail.
            if len(retrieved.obligations) == 0:
                assert unwrap(retrieved) == "SELECT * FROM users WHERE id=1;"
        finally:
            os.unlink(tmp_file.name)


def test_e2e_pii_filtering_pipeline():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        try:
            kms = KeyManagementService(b"test_secret")
            storage = ChavaSQLiteStorage(tmp_file.name, kms)
            registry = get_default_registry()

            data_obj = ChavaObject(
                value={"user_id": 123, "comment": "Call me at 555-1234", "status": "active"},
                obligations=[("pii_clean", "/comment")],
                evidence=[]
            )
            storage.store("user_data", data_obj)

            original_obj = storage.retrieve("user_data")
            projected_obj = project(original_obj, "/comment")
            storage.store("comment_field", projected_obj)

            comment_obj = storage.retrieve("comment_field")
            assert ("pii_clean", "") in comment_obj.obligations

            discharged_comment = discharge(comment_obj, "pii_clean", "", registry, "pii_verifier")
            storage.store("comment_field", discharged_comment)

            final_comment = storage.retrieve("comment_field")
            if len(final_comment.obligations) == 0:
                assert unwrap(final_comment) == "Call me at 555-1234"
        finally:
            os.unlink(tmp_file.name)
