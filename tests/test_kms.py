import pytest
from chava.kms import KeyManagementService, ObligationKeyedStorage, CryptographicException
from chava.core import ChavaObject


def test_kms_derive_key():
    kms = KeyManagementService(b"test_secret")

    key1 = kms.derive_key([("sql_safe", "")], b"test_secret")
    key2 = kms.derive_key([("sql_safe", "")], b"test_secret")
    key3 = kms.derive_key([("pii_clean", "")], b"test_secret")

    assert key1 == key2
    assert key1 != key3


def test_kms_verify_and_release_key_cleared():
    kms = KeyManagementService(b"test_secret")
    obj = ChavaObject(value="test_data", obligations=[], evidence=[])
    assert kms.verify_and_release_key(obj) is not None


def test_kms_verify_and_release_key_uncleared():
    kms = KeyManagementService(b"test_secret")
    obj = ChavaObject(value="test_data", obligations=[("sql_safe", "")], evidence=[])
    assert kms.verify_and_release_key(obj) is None


def test_storage_prevents_uncleared_access():
    kms = KeyManagementService(b"test_secret")
    storage = ObligationKeyedStorage(kms)

    obj = ChavaObject(value="secret_data", obligations=[("sql_safe", "")], evidence=[])
    storage.store("test_obj", obj)

    with pytest.raises(CryptographicException):
        storage.retrieve("test_obj")


def test_storage_allows_cleared_access():
    kms = KeyManagementService(b"test_secret")
    storage = ObligationKeyedStorage(kms)

    obj = ChavaObject(value="public_data", obligations=[], evidence=[])
    storage.store("test_obj", obj)

    retrieved = storage.retrieve("test_obj")
    assert retrieved.value == "public_data"
