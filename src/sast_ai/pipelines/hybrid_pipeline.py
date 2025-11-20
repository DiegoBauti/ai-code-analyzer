from typing import List, Dict
from collections import defaultdict
from ..core.models import (
    FileContext,
    Finding,
    ScanResult,
    CodeSnippetContext,
    FindingSource,
)
from ..core.config import Config
from ..static_analysis.engine import run_static_analysis
from ..ai.gpt_client import analyze_snippet_with_ai
import math


def build_snippets(files: List[FileContext], static_findings: List[Finding], config: Config) -> List[CodeSnippetContext]:
    max_lines = int(config.get("general", "max_snippet_lines", default=120))
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in static_findings:
        by_file[f.file_path].append(f)

    snippets: List[CodeSnippetContext] = []

    for fc in files:
        lines = fc.content.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            continue

        num_chunks = max(1, math.ceil(total_lines / max_lines))
        for chunk_idx in range(num_chunks):
            start_line = chunk_idx * max_lines + 1
            end_line = min(total_lines, (chunk_idx + 1) * max_lines)
            code = "\n".join(lines[start_line - 1 : end_line])

            related_static = [
                f
                for f in by_file.get(fc.path, [])
                if not (f.end_line < start_line or f.start_line > end_line)
            ]

            snippets.append(
                CodeSnippetContext(
                    file_path=fc.path,
                    start_line=start_line,
                    end_line=end_line,
                    language=fc.language,
                    code=code,
                    static_findings=related_static,
                )
            )

    return snippets


def merge_findings(static_findings: List[Finding], ai_findings: List[Finding]) -> List[Finding]:
    merged: List[Finding] = []

    # Agrupar estáticos por (file, tipo, rango aproximado)
    def key(f: Finding):
        return (
            f.file_path,
            f.vulnerability_type,
            f.severity.value,
            round((f.start_line + f.end_line) / 2),
        )

    static_map: Dict[tuple, Finding] = {}
    for f in static_findings:
        static_map[key(f)] = f

    for ai_f in ai_findings:
        k = key(ai_f)
        if k in static_map:
            s = static_map[k]
            # fusionar como HYBRID
            avg_conf = (s.confidence + ai_f.confidence) / 2.0
            s.confidence = avg_conf
            s.source = FindingSource.HYBRID
            merged.append(s)
            del static_map[k]
        else:
            merged.append(ai_f)

    # añadir los estáticos que no fueron confirmados por IA
    merged.extend(static_map.values())
    return merged


def compute_summary(findings: List[Finding]) -> dict:
    summary: Dict[str, any] = {
        "total_findings": len(findings),
        "by_severity": defaultdict(int),
        "by_source": defaultdict(int),
        "by_type": defaultdict(int),
    }

    for f in findings:
        summary["by_severity"][f.severity.value] += 1
        summary["by_source"][f.source.value] += 1
        summary["by_type"][f.vulnerability_type] += 1

    # convertir defaultdict a dict normal
    summary["by_severity"] = dict(summary["by_severity"])
    summary["by_source"] = dict(summary["by_source"])
    summary["by_type"] = dict(summary["by_type"])

    return summary


def run_hybrid_scan(root_path: str, language: str, files: List[FileContext], config: Config) -> ScanResult:
    # 1) capa estática
    static_findings = run_static_analysis(files, config)

    # 2) snippets para IA
    use_ai = config.get("ai", "enabled", default=True)
    ai_findings: List[Finding] = []

    if use_ai:
        snippets = build_snippets(files, static_findings, config)
        for snippet in snippets:
            try:
                ai_findings.extend(analyze_snippet_with_ai(snippet, config))
            except Exception:
                # para prototipo: ignorar errores de IA
                continue

    # 3) fusionar
    all_findings = merge_findings(static_findings, ai_findings)
    summary = compute_summary(all_findings)

    return ScanResult(
        root_path=root_path,
        findings=all_findings,
        summary=summary,
    )
