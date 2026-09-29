from __future__ import annotations

import asyncio
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from anomaly_detection.engine import AnomalyEngine


async def _run() -> None:
    console = Console()
    engine = AnomalyEngine()
    try:
        result = await engine.evaluate()
    finally:
        await engine.aclose()

    console.print(
        Panel.fit(
            f"Evaluated [bold]{result.series_count}[/] series → "
            f"[bold]{result.anomaly_count}[/] anomalies → "
            f"[bold]{result.incident_count}[/] incidents",
            title="K8s Anomaly Detection Demo",
        )
    )

    table = Table(title="Incidents")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("Service")
    table.add_column("Signals")
    table.add_column("Narrative")

    for incident in result.incidents:
        table.add_row(
            f"{incident.score:.0f}",
            incident.severity.value,
            f"{incident.namespace}/{incident.service}",
            ", ".join(s.signal.value for s in incident.signals),
            incident.narrative,
        )
    console.print(table)

    if result.incidents:
        top = result.incidents[0]
        console.print("\n[bold]Top incident JSON[/]")
        console.print_json(json.dumps(top.model_dump(mode="json"), indent=2))


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
