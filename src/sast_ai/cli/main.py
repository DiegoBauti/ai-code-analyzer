import os
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.filesystem import discover_files
from ..pipelines.hybrid_pipeline import run_hybrid_scan
from ..pipelines.exporters import export_result

app = typer.Typer(help="SAST híbrido (estático + IA) para detección de vulnerabilidades.")


console = Console()


@app.command()
def scan(
    path: str = typer.Argument(".", help="Ruta al proyecto a analizar."),
    language: str = typer.Option("python", "--language", "-l", help="Lenguaje principal del proyecto."),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta al archivo de configuración YAML."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Archivo de salida (JSON/MD)."),
    fmt: str = typer.Option("json", "--format", "-f", help="Formato de salida: json o md."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Deshabilitar el uso de IA aunque esté en la config."),
):
    """
    Ejecuta un análisis híbrido (estático + IA) sobre el código fuente.
    """

    config = Config.load(config_path)

    if no_ai:
        config.data.setdefault("ai", {})
        config.data["ai"]["enabled"] = False

    root_path = os.path.abspath(path)
    console.print(f"[bold]Analizando[/bold] {root_path} (language={language})")

    files = discover_files(root_path, language, config)
    if not files:
        console.print("[yellow]No se encontraron archivos para analizar.[/yellow]")
        raise typer.Exit(code=1)

    console.print(f"Archivos encontrados: {len(files)}")

    result = run_hybrid_scan(root_path, language, files, config)

    # Mostrar resumen breve en consola
    table = Table(title="Resumen de hallazgos")
    table.add_column("Total")
    table.add_column("Severidad")
    table.add_column("Fuente")

    sev_summary = result.summary.get("by_severity", {})
    src_summary = result.summary.get("by_source", {})
    total = result.summary.get("total_findings", 0)
    table.add_row(
        str(total),
        ", ".join(f"{k}:{v}" for k, v in sev_summary.items()) or "-",
        ", ".join(f"{k}:{v}" for k, v in src_summary.items()) or "-",
    )
    console.print(table)

    output_text = export_result(result, fmt=fmt)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(output_text)
        console.print(f"[green]Resultado guardado en[/green] {output}")
    else:
        console.print(output_text)


if __name__ == "__main__":
    app()
