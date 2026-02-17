import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from typing import List, Tuple, Optional, Dict, Any
from .core import ChavaObject, verify_evidence_chain, has_conflict


class CryptographicException(Exception):
    """Raised when KMS refuses to release decryption key"""
    pass


class KeyManagementService:
    """
    Simulates KMS for obligation-keyed encryption.
    In production: would be external service like AWS KMS or HashiCorp Vault.
    """

    def __init__(self, server_secret: bytes):
        self.server_secret = server_secret

    def derive_key(self, obligations: List[Tuple[str, str]],
                   server_secret: bytes) -> bytes:
        """
        Derive encryption key using KDF (Key Derivation Function).
        K_O = KDF(hash(O), σ) where σ is server-side secret.
        Uses PBKDF2 with SHA-256.
        """
        # Normalize obligations into list[tuple[str,str]] even if loaded from JSON
        norm = [(k, s) for k, s in obligations]  # works for tuple or list pairs

        obl_str = str(sorted(norm))  # canonical
        obl_hash = hashlib.sha256(obl_str.encode()).digest()

        #obl_str = str(sorted(obligations))
        #obl_hash = hashlib.sha256(obl_str.encode()).digest()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=obl_hash,
            iterations=100000,
        )
        key = kdf.derive(server_secret)
        return key

    def verify_and_release_key(self, obj: ChavaObject) -> Optional[bytes]:
        """
        Verify evidence log, check for conflicts, confirm all obligations discharged.
        Release K_∅ (cleared key) only if object is cleared.
        Returns None if object is not cleared.
        """
        if len(obj.obligations) > 0:
            return None

        if not verify_evidence_chain(obj.evidence):
            return None

        if has_conflict(obj.evidence):
            return None

        cleared_key = self.derive_key([], self.server_secret)
        return cleared_key


class ObligationKeyedStorage:
    """
    Storage where value is encrypted with AES-256-GCM using obligation-derived key.
    Value is cryptographically inaccessible without KMS verification.
    """

    def __init__(self, kms: KeyManagementService):
        self.kms = kms
        self.storage = {}  # obj_id -> (encrypted_value, obligations, evidence)

    def store(self, obj_id: str, obj: ChavaObject) -> None:
        encryption_key = self.kms.derive_key(obj.obligations, self.kms.server_secret)

        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        value_bytes = obj.value if isinstance(obj.value, bytes) else str(obj.value).encode()
        encrypted_value = aesgcm.encrypt(nonce, value_bytes, None)

        stored_data = nonce + encrypted_value
        self.storage[obj_id] = (stored_data, obj.obligations, obj.evidence)

    def retrieve(self, obj_id: str) -> ChavaObject:
        if obj_id not in self.storage:
            raise KeyError(f"Object {obj_id} not found")

        stored_data, obligations, evidence = self.storage[obj_id]
        temp_obj = ChavaObject(None, obligations, evidence)

        key = self.kms.verify_and_release_key(temp_obj)
        if key is None:
            raise CryptographicException(
                f"Cannot decrypt object {obj_id}: not cleared or verification failed"
            )

        nonce = stored_data[:12]
        ciphertext = stored_data[12:]
        aesgcm = AESGCM(key)
        decrypted_value = aesgcm.decrypt(nonce, ciphertext, None)

        return ChavaObject(decrypted_value.decode(), obligations, evidence)
