import json
from typing import List
from ..core.models import ScanResult, Finding


def export_to_json(result: ScanResult) -> str:
    return result.json(indent=2, ensure_ascii=False)


def export_to_markdown(result: ScanResult) -> str:
    lines = []
    lines.append(f"# Resultados de análisis - {result.root_path}")
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    lines.append(f"- Total de hallazgos: **{result.summary.get('total_findings', 0)}**")
    lines.append("- Por severidad:")
    for sev, count in result.summary.get("by_severity", {}).items():
        lines.append(f"  - {sev}: {count}")
    lines.append("- Por fuente:")
    for src, count in result.summary.get("by_source", {}).items():
        lines.append(f"  - {src}: {count}")
    lines.append("")
    lines.append("## Detalle de vulnerabilidades")
    lines.append("")
    lines.append("| Archivo | Línea | Tipo | Severidad | Fuente | Confianza | Descripción |")
    lines.append("|---------|-------|------|-----------|--------|-----------|-------------|")

    def short(text: str, length: int = 80) -> str:
        text = text.replace("\n", " ")
        return text[: length] + ("..." if len(text) > length else "")

    for f in result.findings:
        lines.append(
            "| {file} | {line} | {type} | {sev} | {src} | {conf:.2f} | {desc} |".format(
                file=f.file_path,
                line=f.start_line,
                type=f.vulnerability_type,
                sev=f.severity.value,
                src=f.source.value,
                conf=f.confidence,
                desc=short(f.description),
            )
        )

    return "\n".join(lines)


def export_result(result: ScanResult, fmt: str = "json") -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return export_to_json(result)
    elif fmt in ("md", "markdown"):
        return export_to_markdown(result)
    else:
        raise ValueError(f"Formato de salida no soportado: {fmt}")
