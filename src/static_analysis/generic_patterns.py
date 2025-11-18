import re
from typing import List
from ..core.models import Finding, FindingSource, Severity
import uuid

SQL_PATTERN = re.compile(
    r"(select|insert|update|delete)\s+.+\s+from\s+",
    re.IGNORECASE | re.MULTILINE,
)

HARDCODED_PASSWORD_PATTERN = re.compile(
    r"(password|passwd|pwd)\s*=\s*['\"].+['\"]",
    re.IGNORECASE,
)


def analyze_generic(file_path: str, code: str) -> List[Finding]:

    findings: List[Finding] = []

    for match in SQL_PATTERN.finditer(code):
        start_line = code[: match.start()].count("\n") + 1
        end_line = code[: match.end()].count("\n") + 1
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                vulnerability_type="Potential raw SQL query",
                cwe_id="CWE-89",
                severity=Severity.MEDIUM,
                description="Se detectó un posible uso de SQL sin parametrización.",
                recommendation="Utilice consultas parametrizadas/preparadas o un ORM seguro.",
                confidence=0.5,
                source=FindingSource.STATIC,
                raw_evidence={"pattern": "SQL_PATTERN"},
            )
        )

    for match in HARDCODED_PASSWORD_PATTERN.finditer(code):
        start_line = code[: match.start()].count("\n") + 1
        end_line = code[: match.end()].count("\n") + 1
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                vulnerability_type="Hardcoded credential",
                cwe_id="CWE-259",
                severity=Severity.HIGH,
                description="Posible contraseña embebida en el código.",
                recommendation="Evite credenciales hardcodeadas. Use variables de entorno o un gestor de secretos.",
                confidence=0.8,
                source=FindingSource.STATIC,
                raw_evidence={"pattern": "HARDCODED_PASSWORD_PATTERN"},
            )
        )

    return findings