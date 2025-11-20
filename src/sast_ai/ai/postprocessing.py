import json
from typing import List
from ..core.models import CodeSnippetContext, Finding, Severity, FindingSource
import uuid


def parse_ai_response(snippet: CodeSnippetContext, raw_text: str, min_confidence: float) -> List[Finding]:
    findings: List[Finding] = []
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return findings

    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return findings

    for v in vulns:
        try:
            if not v.get("is_vulnerability", False):
                continue
            confidence = float(v.get("confidence", 0.0))
            if confidence < min_confidence:
                continue

            severity_str = str(v.get("severity", "medium")).lower()
            if severity_str not in ("low", "medium", "high", "critical"):
                severity_str = "medium"

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    file_path=snippet.file_path,
                    start_line=int(v.get("start_line", snippet.start_line)),
                    end_line=int(v.get("end_line", snippet.end_line)),
                    vulnerability_type=str(v.get("vulnerability_type", "Unspecified")),
                    cwe_id=v.get("cwe_id"),
                    severity=Severity(severity_str),
                    description=str(v.get("description", "")),
                    recommendation=str(v.get("recommendation", "")),
                    confidence=confidence,
                    source=FindingSource.AI,
                    raw_evidence={"raw": v},
                )
            )
        except Exception:
            continue

    return findings
