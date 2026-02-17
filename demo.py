#!/usr/bin/env python3
"""
Interactive demonstration of the Chava system showing all key scenarios.
"""

from chava.core import ChavaObject, unwrap, discharge, ObligationViolation
from chava.verifiers import get_default_registry
from chava.algebra import project
from chava.kms import KeyManagementService
from chava.sqlite_storage import ChavaSQLiteStorage
from rich.console import Console
from rich.panel import Panel
import time


console = Console()


def demo_intro():
    console.print(Panel.fit(
        "[bold blue]Welcome to Chava Demo\n"
        "[white]A Verification-Aware Data Model for Trust-Carrying Data Processing",
        border_style="blue"
    ))

    console.print("\nThis demo will walk you through:")
    console.print("• LLM-Generated SQL protection")
    console.print("• PII filtering with scoped obligations")
    console.print("• ETL compliance with conflict detection")
    console.print("• Persistent storage and batch operations")

    input("\nPress Enter to begin...")


def demo_llm_sql_scenario():
    console.rule("[bold green]Scenario 1: LLM-Generated SQL Protection")

    console.print("\n[blue]Step 1:[/blue] Creating object with SQL that needs verification")
    sql_obj = ChavaObject(
        value="SELECT * FROM users WHERE id=1;",
        obligations=[("sql_safe", "")],
        evidence=[]
    )
    console.print(f"SQL Query: {sql_obj.value}")
    console.print(f"Obligations: {sql_obj.obligations}")

    console.print("\n[blue]Step 2:[/blue] Attempting to unwrap (should fail)")
    try:
        _ = unwrap(sql_obj)
        console.print("[red]ERROR: Should not have succeeded![/red]")
    except ObligationViolation as e:
        console.print(f"[yellow]✓ Correctly blocked: {e}[/yellow]")

    console.print("\n[blue]Step 3:[/blue] Setting up storage and verifiers")
    kms = KeyManagementService(b"demo_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)
    registry = get_default_registry()

    storage.store("sql_query", sql_obj)
    console.print("[green]✓ Object stored in secure storage[/green]")

    console.print("\n[blue]Step 4:[/blue] Discharging the obligation")
    obj = storage.retrieve("sql_query")
    discharged_obj = discharge(obj, "sql_safe", "", registry, "demo_sql_verifier")
    storage.store("sql_query", discharged_obj)

    console.print(f"[green]✓ Obligation discharged[/green]")
    console.print(f"Remaining obligations: {discharged_obj.obligations}")

    console.print("\n[blue]Step 5:[/blue] Now unwrapping succeeds")
    try:
        final_value = unwrap(discharged_obj)
        console.print(f"[green]✓ Successfully unwrapped: {final_value}[/green]")
    except ObligationViolation as e:
        console.print(f"[red]ERROR: {e}[/red]")

    input("\nPress Enter to continue...")


def demo_pii_filtering_scenario():
    console.rule("[bold green]Scenario 2: PII Filtering with Scoped Obligations")

    console.print("\n[blue]Step 1:[/blue] Creating object with PII in specific field")
    personal_data = {
        "user_id": 123,
        "name": "John Doe",
        "comment": "Call me at 555-1234 for urgent matters",
        "status": "active"
    }

    obj = ChavaObject(
        value=personal_data,
        obligations=[("pii_clean", "/comment")],
        evidence=[]
    )

    console.print(f"Data: {obj.value}")
    console.print(f"Obligations: {obj.obligations} (only /comment field)")

    console.print("\n[blue]Step 2:[/blue] Projecting to the sensitive field")
    projected = project(obj, "/comment")
    console.print(f"Projected value: {projected.value}")
    console.print(f"Projected obligations: {projected.obligations}")

    console.print("\n[blue]Step 3:[/blue] Storing and discharging on projected object")
    kms = KeyManagementService(b"demo_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)
    registry = get_default_registry()

    storage.store("comment_field", projected)

    proj_obj = storage.retrieve("comment_field")
    discharged_proj = discharge(proj_obj, "pii_clean", "", registry, "demo_pii_verifier")
    storage.store("comment_field", discharged_proj)

    console.print("[green]✓ PII obligation discharged on projected field[/green]")

    console.print("\n[blue]Step 4:[/blue] Unwrapping the cleaned field")
    try:
        clean_comment = unwrap(discharged_proj)
        console.print(f"[green]✓ Cleaned comment: {clean_comment}[/green]")
    except ObligationViolation as e:
        console.print(f"[red]ERROR: {e}[/red]")

    input("\nPress Enter to continue...")


def demo_conflict_scenario():
    console.rule("[bold green]Scenario 3: Conflict Detection")

    console.print("\n[blue]Step 1:[/blue] Creating an object that will have a conflict")
    console.print("We will construct evidence that has a reject followed by accept.")

    conflicted_obj = ChavaObject(
        value="data_with_conflict",
        obligations=[],
        evidence=[
            {
                "verifier_id": "strict_verifier",
                "result": "reject",
                "timestamp": time.time(),
                "prev_hash": "",
                "kind": "quality_check",
                "scope": "",
                "hash": "dummy_hash_1"
            },
            {
                "verifier_id": "lenient_verifier",
                "result": "accept",
                "timestamp": time.time() + 1,
                "prev_hash": "dummy_hash_1",
                "kind": "quality_check",
                "scope": "",
                "hash": "dummy_hash_2"
            }
        ]
    )

    from chava.core import has_conflict
    console.print(f"Evidence: {[e['result'] for e in conflicted_obj.evidence]}")
    console.print(f"Has conflict: {has_conflict(conflicted_obj.evidence)}")

    console.print("\n[blue]Step 2:[/blue] Showing that conflicted objects can't be unwrapped")
    try:
        unwrap(conflicted_obj)
        console.print("[red]ERROR: Should not have unwrapped![/red]")
    except ObligationViolation:
        console.print("[green]✓ Correctly prevented unwrap of conflicted object[/green]")

    input("\nPress Enter to continue...")


def demo_batch_processing():
    console.rule("[bold green]Scenario 4: Batch Processing")

    queries = [
        "SELECT * FROM users;",
        "SELECT name, email FROM customers;",
        "SELECT COUNT(*) FROM orders;",
        "SELECT product FROM inventory;",
        "SELECT * FROM public_data;",
        "DROP TABLE users;",
        "DELETE FROM customers;",
        "UPDATE accounts SET balance=999999;"
    ]

    objects = []
    for i, query in enumerate(queries):
        obj = ChavaObject(
            value=query,
            obligations=[("sql_safe", "")],
            evidence=[]
        )
        objects.append((f"query_{i}", obj))

    kms = KeyManagementService(b"batch_demo_secret")
    storage = ChavaSQLiteStorage(":memory:", kms)
    registry = get_default_registry()

    for obj_id, obj in objects:
        storage.store(obj_id, obj)

    console.print(f"[green]✓ Stored {len(objects)} objects in database[/green]")

    obj_ids = [obj_id for obj_id, _ in objects]
    results = storage.batch_discharge(obj_ids, "sql_safe", registry, "batch_verifier")

    successful = sum(1 for success in results.values() if success)
    console.print(f"[green]✓ Batch processed {successful}/{len(results)}[/green]")

    cleared_count = 0
    uncleared_count = 0
    for obj_id, _ in objects:
        try:
            obj = storage.retrieve(obj_id)
            if len(obj.obligations) == 0:
                cleared_count += 1
            else:
                uncleared_count += 1
        except Exception:
            uncleared_count += 1

    console.print(f"Final status: {cleared_count} cleared, {uncleared_count} uncleared")
    input("\nPress Enter to finish demo...")


def main():
    demo_intro()
    demo_llm_sql_scenario()
    demo_pii_filtering_scenario()
    demo_conflict_scenario()
    demo_batch_processing()

    console.rule("[bold green]Demo Complete!")
    console.print("\n[blue]Key Takeaways:[/blue]")
    console.print("• Data carries its own verification requirements")
    console.print("• Consumption is gated on verification completion")
    console.print("• Cryptographic enforcement prevents bypass")
    console.print("• Scoped obligations work with field projection")
    console.print("• Conflict detection prevents policy violations")
    console.print("• Batch operations enable high throughput")


if __name__ == "__main__":
    main()
