from chava.core import ChavaObject, unwrap, ObligationViolation
from chava.verifiers import get_default_registry
from chava.algebra import project
from chava.core import discharge
from chava.kms import KeyManagementService
from chava.sqlite_storage import ChavaSQLiteStorage
from rich.console import Console
from rich.table import Table
import json
import time


console = Console()


def example_llm_sql():
    console.rule("[bold blue]LLM-Generated SQL Scenario")

    registry = get_default_registry()
    kms = KeyManagementService(b"example_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)

    sql_query = "SELECT * FROM users WHERE id=1;"
    obj = ChavaObject(
        value=sql_query,
        obligations=[("sql_safe", "")],
        evidence=[]
    )

    console.print(f"[green]✓ Created object with SQL: {sql_query}[/green]")
    console.print(f"Obligations: {obj.obligations}")

    try:
        _ = unwrap(obj)
        console.print("[red]✗ ERROR: Should have failed to unwrap![/red]")
    except ObligationViolation as e:
        console.print(f"[yellow]✓ Correctly failed to unwrap: {e}[/yellow]")

    storage.store("sql_obj", obj)

    discharged_obj = discharge(obj, "sql_safe", "", registry, "sql_verifier_v1")
    storage.store("sql_obj", discharged_obj)

    console.print(f"[green]✓ Discharged sql_safe obligation[/green]")
    console.print(f"Remaining obligations: {discharged_obj.obligations}")

    try:
        value = unwrap(discharged_obj)
        console.print(f"[green]✓ Successfully unwrapped: {value}[/green]")
    except ObligationViolation as e:
        console.print(f"[red]✗ Failed to unwrap after discharge: {e}[/red]")

    console.rule()


def example_pii_filtering():
    console.rule("[bold blue]PII Filtering Scenario")

    registry = get_default_registry()
    kms = KeyManagementService(b"example_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)

    data = {
        "user_id": 123,
        "comment": "Call me at 555-1234 for more info",
        "status": "active"
    }

    obj = ChavaObject(
        value=data,
        obligations=[("pii_clean", "/comment")],
        evidence=[]
    )

    console.print(f"[green]✓ Created object with PII in comment field[/green]")
    console.print(f"Data: {json.dumps(data, indent=2)}")
    console.print(f"Obligations: {obj.obligations}")

    projected_obj = project(obj, "/comment")
    console.print(f"[green]✓ Projected to /comment[/green]")
    console.print(f"Projected value: {projected_obj.value}")
    console.print(f"Projected obligations: {projected_obj.obligations}")

    discharged_projected = discharge(projected_obj, "pii_clean", "", registry, "pii_verifier_v1")
    console.print(f"[green]✓ Discharged pii_clean on projected object[/green]")
    console.print(f"After discharge: {discharged_projected.obligations}")

    try:
        value = unwrap(discharged_projected)
        console.print(f"[green]✓ Successfully unwrapped projected object: {value}[/green]")
    except ObligationViolation as e:
        console.print(f"[red]✗ Failed to unwrap projected object: {e}[/red]")

    discharged_original = discharge(obj, "pii_clean", "/comment", registry, "pii_verifier_v1")
    console.print(f"[green]✓ Discharged pii_clean on original object[/green]")
    console.print(f"Original after discharge: {discharged_original.obligations}")

    console.rule()


def example_etl_compliance():
    console.rule("[bold blue]ETL Compliance Scenario")

    registry = get_default_registry()
    kms = KeyManagementService(b"example_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)

    data = {"acct": "A1234", "balance": 5000}
    obj = ChavaObject(
        value=data,
        obligations=[("gdpr_min", ""), ("schema_ok", "")],
        evidence=[]
    )

    console.print(f"[green]✓ Created object with dual obligations[/green]")
    console.print(f"Data: {json.dumps(data, indent=2)}")
    console.print(f"Obligations: {obj.obligations}")

    obj_after_gdpr = discharge(obj, "gdpr_min", "", registry, "gdpr_verifier_v1")
    console.print(f"[green]✓ Discharged gdpr_min[/green]")
    console.print(f"Remaining obligations: {obj_after_gdpr.obligations}")

    bad_data = {"acct": "A1234", "balance": "invalid_type"}
    bad_obj = ChavaObject(
        value=bad_data,
        obligations=[("schema_ok", "")],
        evidence=[]
    )

    rejected_obj = discharge(bad_obj, "schema_ok", "", registry, "schema_verifier_v1")
    console.print(f"[green]✓ Schema validator rejected (as expected)[/green]")
    console.print(f"Obligations after rejection: {rejected_obj.obligations}")

    from chava.core import has_conflict
    console.print(f"Has conflict: {has_conflict(rejected_obj.evidence)}")

    console.print("\n[blue]Creating conflict scenario (reject then accept):[/blue]")

    true_conflict_obj = ChavaObject(
        value={"id": 1, "name": "test"},
        obligations=[("schema_ok", "")],
        evidence=[
            {
                "verifier_id": "strict_verifier",
                "result": "reject",
                "timestamp": time.time(),
                "prev_hash": "",
                "kind": "schema_ok",
                "scope": "",
                "hash": "dummy_hash_1"
            },
            {
                "verifier_id": "lenient_verifier",
                "result": "accept",
                "timestamp": time.time() + 1,
                "prev_hash": "dummy_hash_1",
                "kind": "schema_ok",
                "scope": "",
                "hash": "dummy_hash_2"
            }
        ]
    )

    is_conflicted = has_conflict(true_conflict_obj.evidence)
    console.print(f"True conflict object has conflict: {is_conflicted}")

    try:
        unwrap(true_conflict_obj)
        console.print("[red]✗ ERROR: Should not be able to unwrap conflicted object![/red]")
    except ObligationViolation:
        console.print("[green]✓ Correctly prevented unwrap of conflicted object[/green]")

    console.rule()


def run_all_examples():
    example_llm_sql()
    example_pii_filtering()
    example_etl_compliance()


if __name__ == "__main__":
    run_all_examples()
