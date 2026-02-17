import sqlite3
import json
from typing import List, Tuple, Optional, Dict, Any
from .core import ChavaObject
from .kms import KeyManagementService, CryptographicException


class StorageMetrics:
    """Track storage performance and statistics."""

    def __init__(self):
        self.store_times = []
        self.retrieve_times = []

    def record_store_time(self, duration_ms: float) -> None:
        self.store_times.append(duration_ms)

    def record_retrieve_time(self, duration_ms: float) -> None:
        self.retrieve_times.append(duration_ms)

    def get_stats(self) -> Dict[str, Any]:
        import statistics

        stats = {
            "store_ops": len(self.store_times),
            "retrieve_ops": len(self.retrieve_times)
        }

        if self.store_times:
            stats.update({
                "avg_store_time_ms": statistics.mean(self.store_times),
                "p50_store_time_ms": statistics.median(self.store_times),
                "p95_store_time_ms": self._percentile(self.store_times, 95),
                "p99_store_time_ms": self._percentile(self.store_times, 99),
            })

        if self.retrieve_times:
            stats.update({
                "avg_retrieve_time_ms": statistics.mean(self.retrieve_times),
                "p50_retrieve_time_ms": statistics.median(self.retrieve_times),
                "p95_retrieve_time_ms": self._percentile(self.retrieve_times, 95),
                "p99_retrieve_time_ms": self._percentile(self.retrieve_times, 99),
            })

        return stats

    def _percentile(self, data: List[float], percentile: float) -> float:
        size = len(data)
        if size == 0:
            return 0.0
        idx = int(size * percentile / 100)
        idx = min(max(idx, 0), size - 1)
        return sorted(data)[idx]


class ChavaSQLiteStorage:
    """
    Persistent storage for Chava objects using SQLite.
    """

    def __init__(self, db_path: str, kms: KeyManagementService):
        self.db_path = db_path
        self.kms = kms
        self.metrics = StorageMetrics()
        self.init_database()

    def init_database(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chava_objects (
                    obj_id TEXT PRIMARY KEY,
                    value_encrypted BLOB,
                    obligations_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS obligation_index (
                    obj_id TEXT,
                    kind TEXT,
                    scope TEXT,
                    PRIMARY KEY (obj_id, kind, scope),
                    FOREIGN KEY (obj_id) REFERENCES chava_objects(obj_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_index (
                    obj_id TEXT,
                    verifier_id TEXT,
                    timestamp REAL,
                    result TEXT,
                    FOREIGN KEY (obj_id) REFERENCES chava_objects(obj_id)
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obj_kind ON obligation_index(kind)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obj_verifier ON evidence_index(verifier_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obj_timestamp ON evidence_index(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_obj_result ON evidence_index(result)")

            conn.commit()

    def store(self, obj_id: str, obj: ChavaObject) -> None:
        import time
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        start_time = time.time()

        encryption_key = self.kms.derive_key(obj.obligations, self.kms.server_secret)

        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        value_bytes = json.dumps(obj.value).encode() if not isinstance(obj.value, bytes) else obj.value
        encrypted_value = aesgcm.encrypt(nonce, value_bytes, None)

        stored_data = nonce + encrypted_value

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO chava_objects
                (obj_id, value_encrypted, obligations_json, evidence_json, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                obj_id,
                stored_data,
                json.dumps(obj.obligations),
                json.dumps(obj.evidence)
            ))

            cursor.execute("DELETE FROM obligation_index WHERE obj_id = ?", (obj_id,))
            for kind, scope in obj.obligations:
                cursor.execute("""
                    INSERT INTO obligation_index (obj_id, kind, scope)
                    VALUES (?, ?, ?)
                """, (obj_id, kind, scope))

            cursor.execute("DELETE FROM evidence_index WHERE obj_id = ?", (obj_id,))
            for evidence_record in obj.evidence:
                cursor.execute("""
                    INSERT INTO evidence_index (obj_id, verifier_id, timestamp, result)
                    VALUES (?, ?, ?, ?)
                """, (
                    obj_id,
                    evidence_record["verifier_id"],
                    evidence_record["timestamp"],
                    evidence_record["result"]
                ))

            conn.commit()

        end_time = time.time()
        self.metrics.record_store_time((end_time - start_time) * 1000)

    def retrieve(self, obj_id: str) -> ChavaObject:
        import time
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        start_time = time.time()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT value_encrypted, obligations_json, evidence_json
                FROM chava_objects
                WHERE obj_id = ?
            """, (obj_id,))

            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"Object {obj_id} not found")

        stored_data, obligations_json, evidence_json = row
        obligations = json.loads(obligations_json)
        # normalize lists -> tuples
        obligations = [(k, s) for k, s in obligations]
        evidence = json.loads(evidence_json)

        temp_obj = ChavaObject(None, obligations, evidence)

        # Trusted storage: decrypt using the obligation-derived key (same as store()).
        # Untrusted consumers should use ObligationKeyedStorage, which enforces cleared-only release.
        key = self.kms.derive_key(obligations, self.kms.server_secret)
        '''
        key = self.kms.verify_and_release_key(temp_obj)
        if key is None:
            raise CryptographicException(
                f"Cannot decrypt object {obj_id}: not cleared or verification failed"
            )
        '''
        nonce = stored_data[:12]
        ciphertext = stored_data[12:]

        aesgcm = AESGCM(key)
        decrypted_value = aesgcm.decrypt(nonce, ciphertext, None)

        parsed_value = json.loads(decrypted_value.decode())

        end_time = time.time()
        self.metrics.record_retrieve_time((end_time - start_time) * 1000)

        return ChavaObject(parsed_value, obligations, evidence)

    def query_by_obligation(self, kind: str, scope: Optional[str] = None) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            if scope is None:
                cursor.execute("""
                    SELECT DISTINCT obj_id
                    FROM obligation_index
                    WHERE kind = ?
                """, (kind,))
            else:
                cursor.execute("""
                    SELECT obj_id
                    FROM obligation_index
                    WHERE kind = ? AND scope = ?
                """, (kind, scope))

            return [row[0] for row in cursor.fetchall()]

    def query_by_verifier(self, verifier_id: str,
                         start_time: Optional[float] = None,
                         end_time: Optional[float] = None) -> List[Tuple[str, Dict]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            if start_time is not None and end_time is not None:
                cursor.execute("""
                    SELECT e.obj_id, o.evidence_json
                    FROM evidence_index e
                    JOIN chava_objects o ON e.obj_id = o.obj_id
                    WHERE e.verifier_id = ?
                      AND e.timestamp >= ?
                      AND e.timestamp <= ?
                    ORDER BY e.timestamp
                """, (verifier_id, start_time, end_time))
            elif start_time is not None:
                cursor.execute("""
                    SELECT e.obj_id, o.evidence_json
                    FROM evidence_index e
                    JOIN chava_objects o ON e.obj_id = o.obj_id
                    WHERE e.verifier_id = ?
                      AND e.timestamp >= ?
                    ORDER BY e.timestamp
                """, (verifier_id, start_time))
            elif end_time is not None:
                cursor.execute("""
                    SELECT e.obj_id, o.evidence_json
                    FROM evidence_index e
                    JOIN chava_objects o ON e.obj_id = o.obj_id
                    WHERE e.verifier_id = ?
                      AND e.timestamp <= ?
                    ORDER BY e.timestamp
                """, (verifier_id, end_time))
            else:
                cursor.execute("""
                    SELECT e.obj_id, o.evidence_json
                    FROM evidence_index e
                    JOIN chava_objects o ON e.obj_id = o.obj_id
                    WHERE e.verifier_id = ?
                    ORDER BY e.timestamp
                """, (verifier_id,))

            results = []
            for obj_id, evidence_json in cursor.fetchall():
                evidence_list = json.loads(evidence_json)
                if evidence_list:
                    results.append((obj_id, evidence_list[0]))

            return results

    def batch_discharge(self, obj_ids: List[str], kind: str,
                       registry, verifier_id: str) -> Dict[str, bool]:
        results = {}

        for obj_id in obj_ids:
            try:
                obj = self.retrieve(obj_id)
                from .core import discharge
                discharged_obj = discharge(obj, kind, "", registry, verifier_id)
                self.store(obj_id, discharged_obj)
                results[obj_id] = True
            except Exception as e:
                print(f"Failed to discharge {obj_id}: {e}")
                results[obj_id] = False

        return results


def init_database(db_path: str) -> None:
    ChavaSQLiteStorage(db_path, KeyManagementService(b"default_secret"))
