from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
import uuid


class FindingSource(str, Enum):
    STATIC = "static"
    AI = "ai"
    HYBRID = "hybrid"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str
    start_line: int
    end_line: int
    vulnerability_type: str

    cwe_id: Optional[str] = None
    severity: Severity = Severity.MEDIUM

    description: str
    recommendation: str

    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confianza del hallazgo (0.0–1.0)"
    )

    source: FindingSource

    raw_evidence: Dict[str, Any] = Field(default_factory=dict)

    is_true_positive: Optional[bool] = Field(
        default=None,
        description="Validación manual: True si es TP, False si es FP, None si no validado"
    )

    @field_validator("end_line")
    def validate_line_range(cls, end_line, values):
        start = values.data.get("start_line", 0)
        if end_line < start:
            raise ValueError("end_line no puede ser menor que start_line")
        return end_line

    def mark_as_true_positive(self):
        self.is_true_positive = True

    def mark_as_false_positive(self):
        self.is_true_positive = False

    def is_validated(self) -> bool:
        return self.is_true_positive is not None


class FileContext(BaseModel):
    path: str
    language: str
    content: str


class CodeSnippetContext(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    language: str
    code: str

    static_findings: List[Finding] = Field(default_factory=list)


class ScanResult(BaseModel):
    root_path: str
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_validated_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_validated()]

    def get_critical_findings(self) -> List[Finding]:
        return self.get_findings_by_severity(Severity.CRITICAL)

    def get_high_findings(self) -> List[Finding]:
        return self.get_findings_by_severity(Severity.HIGH)