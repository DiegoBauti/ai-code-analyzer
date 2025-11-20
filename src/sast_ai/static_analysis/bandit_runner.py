from typing import List
import subprocess
import json
import shutil
from ..core.models import FileContext, Finding, Severity, FindingSource


def run_bandit_on_file(file: FileContext) -> List[Finding]:

    if not shutil.which("bandit"):
        print("️ Bandit no está instalado. Instálalo con: pip install bandit")
        return []

    findings: List[Finding] = []

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", file.path],
            capture_output=True,
            text=True,
            check=False
        )

        if not result.stdout:
            return findings

        data = json.loads(result.stdout)

        severity_map = {
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL
        }

        confidence_map = {
            "LOW": 0.3,
            "MEDIUM": 0.6,
            "HIGH": 0.9
        }

        for issue in data.get("results", []):
            bandit_severity = issue.get("issue_severity", "MEDIUM").upper()
            severity = severity_map.get(bandit_severity, Severity.MEDIUM)

            bandit_confidence = issue.get("issue_confidence", "MEDIUM").upper()
            confidence = confidence_map.get(bandit_confidence, 0.6)

            cwe_data = issue.get("cwe")
            cwe_id = None
            if isinstance(cwe_data, dict) and "id" in cwe_data:
                cwe_id = f"CWE-{cwe_data['id']}"
            elif isinstance(cwe_data, str):
                cwe_id = cwe_data if cwe_data.startswith("CWE-") else f"CWE-{cwe_data}"

            finding = Finding(
                file_path=file.path,
                start_line=issue.get("line_number", 1),
                end_line=issue.get("line_number", 1),
                vulnerability_type=issue.get("test_name", "Bandit Finding"),
                cwe_id=cwe_id,
                severity=severity,
                description=issue.get("issue_text", "Sin descripción"),
                recommendation=f"Revisar regla Bandit: {issue.get('test_id', 'N/A')}. {issue.get('more_info', '')}",
                confidence=confidence,
                source=FindingSource.STATIC,
                raw_evidence={
                    "bandit_test_id": issue.get("test_id"),
                    "more_info": issue.get("more_info", ""),
                    "code": issue.get("code", "")
                }
            )
            findings.append(finding)

    except subprocess.CalledProcessError as e:
        print(f" Error ejecutando Bandit en {file.path}: {e}")
    except json.JSONDecodeError as e:
        print(f"️ No se pudo parsear JSON de Bandit en {file.path}: {e}")
    except Exception as e:
        print(f"️ Error inesperado con Bandit: {e}")

    return findings


def run_bandit(files: List[FileContext]) -> List[Finding]:

    all_findings: List[Finding] = []

    for file in files:
        if file.language != "python":
            continue
        all_findings.extend(run_bandit_on_file(file))

    return all_findings