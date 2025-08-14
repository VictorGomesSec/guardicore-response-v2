from datetime import datetime, timedelta
from uuid import UUID

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc

import typer
from rich import print
from rich.console import Console
from rich.table import Table

from lumudblib.db_client import get_company_incidents

app = typer.Typer()
console = Console()


@app.command()
def list_incidents(
    db_path: str = typer.Option("./ioc.db", prompt=False),
    companyId: UUID = typer.Option("10228d9c-ff18-4251-ac19-514185e00f17", prompt=True),
    days: int = typer.Option(30, prompt=True),
):
    print(f"Recent Incidents: last {days} days.")
    _from = datetime.now(UTC) - timedelta(days=days)
    table = Table("uuid", "Adversary", "Adversary Type", "Status", "Last Contact")
    for inc in get_company_incidents(db_path, str(companyId), _from):
        table.add_row(
            str(inc.id),
            str(inc.adversaryId),
            str(inc.adversaryTypes),
            str(inc.status.value),
            str(inc.lastContact),
        )
    console.print(table)


@app.command()
def list_incident_ioc(
    db_path: str = typer.Option("./ioc.db", prompt=False),
    companyId: UUID = typer.Option("10228d9c-ff18-4251-ac19-514185e00f17", prompt=True),
    days: int = typer.Option(30, prompt=True),
    incidentId: UUID = typer.Option(..., prompt=True),
):
    print(f"Incident and its  IOC's: last {days} days")
    _from = datetime.now(UTC) - timedelta(days=days)
    table = Table("IOC", "IOC Type")
    for inc in get_company_incidents(db_path, str(companyId), _from):
        if inc.id == incidentId:
            [table.add_row(ioc.value, ioc.type.value) for ioc in inc.iocs]
            console.print(table)
            break
    else:
        print(
            f"[bold red]Warning![/bold red] [red]Company ID: {companyId}[/red] - Incident with ID {incidentId} not found in the last {days} days! :boom:"
        )


if __name__ == "__main__":
    app()
