# Chava: A Verification-Aware Data Model for Trust-Carrying Data Processing

Chava is a system that implements a verification-aware data model where data objects carry their own verification requirements (obligations) and evidence of completed verifications, preventing unvalidated data from being consumed.

## Features

- **Trust-Carrying Data**: Values carry their verification requirements and history
- **Obligation Gating**: Consumption is structurally gated on verification completion
- **Cryptographic Enforcement**: Values are encrypted by obligation-derived keys
- **Append-Only Evidence**: Tamper-evident verification logs
- **Projection Safety**: Scoped obligations preserved during field extraction
- **Batch Processing**: Efficient bulk verification operations
- **Persistent Storage**: SQLite-backed storage with indexes

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e .[dev]
```

## Quick Start

### Creating a Chava Object

```python
from chava.core import ChavaObject

obj = ChavaObject(
    value="SELECT * FROM users WHERE id=1;",
    obligations=[("sql_safe", "")],
    evidence=[]
)
```

### Using the CLI

```bash
chava create my_sql --value '"SELECT * FROM users;"' --obligation sql_safe:
chava show my_sql
chava discharge my_sql --kind sql_safe --verifier my_verifier
chava unwrap my_sql
```

### Programmatic Usage

```python
from chava.core import ChavaObject, unwrap, discharge, ObligationViolation
from chava.verifiers import get_default_registry
from chava.kms import KeyManagementService
from chava.sqlite_storage import ChavaSQLiteStorage

kms = KeyManagementService(b"my_secret")
storage = ChavaSQLiteStorage("chava.db", kms)
registry = get_default_registry()

obj = ChavaObject(
    value="SELECT * FROM safe_table;",
    obligations=[("sql_safe", "")],
    evidence=[]
)
storage.store("my_obj", obj)

obj = storage.retrieve("my_obj")
discharged = discharge(obj, "sql_safe", "", registry, "verifier_v1")
storage.store("my_obj", discharged)

try:
    value = unwrap(discharged)
    print(f"Unwrapped value: {value}")
except ObligationViolation as e:
    print(f"Cannot unwrap: {e}")
```

## Architecture

### Core Components

1. **ChavaObject**: Triple ⟨V, O, E⟩ representing value, obligations, and evidence
2. **Verifiers**: Registered functions that validate specific obligation kinds
3. **Storage**: Obligation-keyed encryption with KMS integration
4. **Indexes**: Fast lookup by obligation kind, scope, and verifier activity

### Data Flow

```
[Raw Data] → [Attach Obligations] → [Chava Object] → [Verification] → [Cleared Object] → [Consumption]
```

## Running Tests

```bash
pytest -v
```

Or with coverage:

```bash
pytest --cov=chava --cov-report=html
```

## License

MIT License - see LICENSE file for details.
