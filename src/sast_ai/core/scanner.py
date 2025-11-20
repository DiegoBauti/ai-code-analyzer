from pathlib import Path
from typing import List, Optional

from .filesystem import list_source_files
from ..static_analysis.engine import run_static_analysis
from .models import ScanResult, Finding
from .config import Config


def run_scan(target_path: str, config: Optional[Config] = None) -> ScanResult:

    if config is None:
        config = Config.load()

    project_path = Path(target_path)

    if not project_path.exists():
        raise FileNotFoundError(f"El path no existe: {target_path}")

    all_files = list_source_files(str(project_path))

    files_to_analyze = [f for f in all_files if config.should_analyze_file(f)]

    print(f"Total archivos encontrados: {len(all_files)}")
    print(f"Archivos a analizar: {len(files_to_analyze)}")

    if len(files_to_analyze) == 0:
        print("⚠️  No hay archivos que analizar según la configuración")

    all_findings: List[Finding] = []
    files_with_errors = 0

    for file_path in files_to_analyze:
        try:
            findings = run_static_analysis(file_path, config)
            all_findings.extend(findings)

            if findings:
                print(f"  🔍 {Path(file_path).name}: {len(findings)} finding(s)")

        except Exception as e:
            files_with_errors += 1
            print(f"⚠️  Error analizando {file_path}: {e}")
            continue

    return ScanResult(
        root_path=str(project_path),
        findings=all_findings,
        summary={
            "total_files_discovered": len(all_files),
            "files_analyzed": len(files_to_analyze),
            "files_skipped": len(all_files) - len(files_to_analyze),
            "files_with_errors": files_with_errors,
            "total_findings": len(all_findings),
            "files_with_findings": len(set(f.file_path for f in all_findings)),
            "by_severity": _count_by_severity(all_findings),
            "by_source": _count_by_source(all_findings),
            "by_cwe": _count_by_cwe(all_findings)
        }
    )


def _count_by_severity(findings: List[Finding]) -> dict:
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _count_by_source(findings: List[Finding]) -> dict:
    counts = {"static": 0, "ai": 0, "hybrid": 0}
    for f in findings:
        counts[f.source.value] += 1
    return counts


def _count_by_cwe(findings: List[Finding]) -> dict:
    counts = {}
    for f in findings:
        cwe = f.cwe_id or "unknown"
        counts[cwe] = counts.get(cwe, 0) + 1
    return counts