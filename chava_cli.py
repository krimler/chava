#!/usr/bin/env python3

import click
import json
from rich.console import Console
from rich.table import Table
from chava.core import ChavaObject, unwrap, ObligationViolation
from chava.verifiers import get_default_registry
from chava.algebra import project as project_fn, merge as merge_fn
from chava.kms import KeyManagementService
from chava.sqlite_storage import ChavaSQLiteStorage

console = Console()


@click.group()
@click.option('--db', default='chava.db', help='Database path')
@click.pass_context
def cli(ctx, db):
    """Chava: Trust-Carrying Data Processing CLI"""
    ctx.ensure_object(dict)
    ctx.obj['db_path'] = db

    kms = KeyManagementService(b"chava_default_secret")
    storage = ChavaSQLiteStorage(db, kms)
    registry = get_default_registry()

    ctx.obj['storage'] = storage
    ctx.obj['registry'] = registry
    ctx.obj['kms'] = kms


@cli.command()
@click.argument('obj_id')
@click.option('--value', required=True, help='JSON value')
@click.option('--obligation', multiple=True, help='Obligation as kind:scope')
@click.pass_context
def create(ctx, obj_id, value, obligation):
    """Create a new Chava object."""
    try:
        parsed_value = json.loads(value)
        obligations = []

        for obl in obligation:
            parts = obl.split(':', 1)
            if len(parts) != 2:
                raise click.BadParameter(f"Obligation format must be 'kind:scope', got '{obl}'")
            kind, scope = parts
            obligations.append((kind, scope))

        obj = ChavaObject(parsed_value, obligations, [])
        storage = ctx.obj['storage']
        storage.store(obj_id, obj)

        console.print(f"[green]✓ Created object {obj_id}[/green]")
        console.print(f"Value: {parsed_value}")
        console.print(f"Obligations: {obligations}")

    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON value: {e}[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error creating object: {e}[/red]")


@cli.command()
@click.argument('obj_id')
@click.pass_context
def show(ctx, obj_id):
    """Display Chava object details."""
    try:
        storage = ctx.obj['storage']
        obj = storage.retrieve(obj_id)

        table = Table(title=f"Chava Object {obj_id}")
        table.add_column("Field", style="bold")
        table.add_column("Value")

        try:
            value = unwrap(obj)
            table.add_row("Value", json.dumps(value, indent=2))
        except ObligationViolation:
            table.add_row("Value", "[yellow]ENCRYPTED (not cleared)[/yellow]")

        table.add_row("Status", "Cleared" if len(obj.obligations) == 0 else f"[red]Uncleared ({len(obj.obligations)} pending)[/red]")
        table.add_row("Obligations", json.dumps(obj.obligations, indent=2))
        table.add_row("Evidence Count", str(len(obj.evidence)))

        console.print(table)

        if obj.evidence:
            evidence_table = Table(title="Evidence Log")
            evidence_table.add_column("Time", style="dim")
            evidence_table.add_column("Verifier")
            evidence_table.add_column("Result")
            evidence_table.add_column("Kind")
            evidence_table.add_column("Scope")

            from datetime import datetime
            for record in obj.evidence:
                dt = datetime.fromtimestamp(record['timestamp'])
                evidence_table.add_row(
                    dt.strftime("%Y-%m-%d %H:%M:%S"),
                    record['verifier_id'],
                    record['result'],
                    record.get('kind', ''),
                    record.get('scope', '')
                )

            console.print(evidence_table)

    except KeyError:
        console.print(f"[red]✗ Object {obj_id} not found[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error showing object: {e}[/red]")


@cli.command()
@click.argument('obj_id')
@click.option('--kind', required=True, help='Obligation kind to discharge')
@click.option('--verifier', required=True, help='Verifier ID')
@click.pass_context
def discharge(ctx, obj_id, kind, verifier):
    """Discharge an obligation on an object."""
    try:
        storage = ctx.obj['storage']
        registry = ctx.obj['registry']

        obj = storage.retrieve(obj_id)

        has_obligation = any(k == kind for k, _ in obj.obligations)
        if not has_obligation:
            console.print(f"[yellow]⚠ Object {obj_id} does not have obligation '{kind}'[/yellow]")
            return

        from chava.core import discharge as discharge_func
        discharged_obj = discharge_func(obj, kind, "", registry, verifier)

        storage.store(obj_id, discharged_obj)

        console.print(f"[green]✓ Discharged obligation '{kind}' for object {obj_id}[/green]")

        if any(k == kind for k, _ in discharged_obj.obligations):
            console.print(f"[yellow]Result: Obligation still pending (verifier returned 'reject'/'conditional')[/yellow]")
        else:
            console.print(f"[green]Result: Obligation discharged (verifier returned 'accept')[/green]")

    except KeyError:
        console.print(f"[red]✗ Object {obj_id} not found[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error discharging obligation: {e}[/red]")


@cli.command()
@click.argument('obj_id')
@click.pass_context
def unwrap_cmd(ctx, obj_id):
    """Unwrap and display the value (only if cleared)."""
    try:
        storage = ctx.obj['storage']
        obj = storage.retrieve(obj_id)
        value = unwrap(obj)

        console.print(f"[green]✓ Successfully unwrapped object {obj_id}[/green]")
        console.print(f"Value: {json.dumps(value, indent=2)}")

    except ObligationViolation as e:
        console.print(f"[red]✗ Cannot unwrap: {e}[/red]")
    except KeyError:
        console.print(f"[red]✗ Object {obj_id} not found[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error unwrapping: {e}[/red]")


@cli.command(name="list")
@click.option('--kind', help='Filter by obligation kind')
@click.option('--cleared/--uncleared', default=None, help='Filter by status')
@click.pass_context
def list_objects(ctx, kind, cleared):
    """List objects in database."""
    import sqlite3

    storage: ChavaSQLiteStorage = ctx.obj['storage']
    db_path = storage.db_path

    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT obj_id, obligations_json, evidence_json FROM chava_objects")
        rows = cur.fetchall()

    table = Table(title="Chava Objects")
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Obligations", overflow="fold")
    table.add_column("Evidence Count")

    for obj_id, obligations_json, evidence_json in rows:
        obligations = json.loads(obligations_json)
        evidence = json.loads(evidence_json)
        is_obj_cleared = len(obligations) == 0

        if cleared is not None and is_obj_cleared != cleared:
            continue
        if kind and not any(k == kind for k, _ in obligations):
            continue

        status = "Cleared" if is_obj_cleared else f"[red]Uncleared ({len(obligations)})[/red]"
        obls = str(obligations)
        table.add_row(obj_id, status, (obls[:80] + "...") if len(obls) > 80 else obls, str(len(evidence)))

    console.print(table)


@cli.command()
@click.argument('obj_id')
@click.argument('path')
@click.argument('output_id')
@click.pass_context
def project(ctx, obj_id, path, output_id):
    """Project a field and create new object."""
    try:
        storage = ctx.obj['storage']
        obj = storage.retrieve(obj_id)

        projected_obj = project_fn(obj, path)
        storage.store(output_id, projected_obj)

        console.print(f"[green]✓ Projected {obj_id}:{path} -> {output_id}[/green]")
        console.print(f"Projected value: {json.dumps(projected_obj.value, indent=2)}")
        console.print(f"New obligations: {projected_obj.obligations}")

    except KeyError:
        console.print(f"[red]✗ Object {obj_id} not found[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error projecting: {e}[/red]")


@cli.command()
@click.argument('obj_id1')
@click.argument('obj_id2')
@click.argument('output_id')
@click.pass_context
def merge(ctx, obj_id1, obj_id2, output_id):
    """Merge two objects with AND-conjunction."""
    try:
        storage = ctx.obj['storage']
        obj1 = storage.retrieve(obj_id1)
        obj2 = storage.retrieve(obj_id2)

        merged_obj = merge_fn(obj1, obj2)
        storage.store(output_id, merged_obj)

        console.print(f"[green]✓ Merged {obj_id1} + {obj_id2} -> {output_id}[/green]")
        console.print(f"Combined obligations: {merged_obj.obligations}")

    except KeyError as e:
        console.print(f"[red]✗ Object not found: {e}[/red]")
    except Exception as e:
        console.print(f"[red]✗ Error merging: {e}[/red]")


@cli.command()
@click.option('--verifier', help='Filter by verifier')
@click.option('--since', help='Start timestamp (ISO format)')
@click.option('--until', help='End timestamp (ISO format)')
@click.pass_context
def audit(ctx, verifier, since, until):
    """Query evidence log for audit trail."""
    try:
        storage = ctx.obj['storage']

        start_time = None
        end_time = None

        from datetime import datetime
        if since:
            start_time = datetime.fromisoformat(since.replace('Z', '+00:00')).timestamp()
        if until:
            end_time = datetime.fromisoformat(until.replace('Z', '+00:00')).timestamp()

        if verifier:
            results = storage.query_by_verifier(verifier, start_time, end_time)
        else:
            # fallback: show verifier-indexed results via sqlite
            import sqlite3
            with sqlite3.connect(storage.db_path) as conn:
                cur = conn.cursor()
                query = "SELECT obj_id, verifier_id, timestamp, result FROM evidence_index"
                params = []
                conditions = []
                if start_time is not None:
                    conditions.append("timestamp >= ?")
                    params.append(start_time)
                if end_time is not None:
                    conditions.append("timestamp <= ?")
                    params.append(end_time)
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                query += " ORDER BY timestamp DESC LIMIT 100"
                cur.execute(query, params)
                results = [(row[0], {"verifier_id": row[1], "timestamp": row[2], "result": row[3]})
                           for row in cur.fetchall()]

        if not results:
            console.print("[yellow]No audit records found[/yellow]")
            return

        table = Table(title="Audit Trail")
        table.add_column("Time", style="dim")
        table.add_column("Object ID")
        table.add_column("Verifier")
        table.add_column("Result")

        from datetime import datetime
        for obj_id, record in results[:20]:
            dt = datetime.fromtimestamp(record['timestamp'])
            table.add_row(
                dt.strftime("%Y-%m-%d %H:%M:%S"),
                obj_id,
                record['verifier_id'],
                record['result']
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗ Error querying audit: {e}[/red]")


@cli.command()
@click.pass_context
def stats(ctx):
    """Display database statistics and metrics"""
    try:
        storage = ctx.obj['storage']
        metrics = storage.metrics.get_stats()

        table = Table(title="Storage Metrics")
        table.add_column("Metric", style="bold")
        table.add_column("Value")

        for key, value in metrics.items():
            table.add_row(key, str(value))

        console.print(table)

        import sqlite3
        with sqlite3.connect(storage.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM chava_objects")
            total_objs = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT kind) FROM obligation_index")
            total_kinds = cur.fetchone()[0]

        console.print(f"\nTotal objects: {total_objs}")
        console.print(f"Total obligation kinds: {total_kinds}")

    except Exception as e:
        console.print(f"[red]✗ Error getting stats: {e}[/red]")


if __name__ == '__main__':
    cli(obj={})
