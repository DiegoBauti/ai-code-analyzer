from typing import Dict, Any
from ..core.models import CodeSnippetContext, Finding


def build_messages_for_snippet(snippet: CodeSnippetContext) -> Dict[str, Any]:
    """
    Construye el payload messages para la API de chat de OpenAI.
    """
    static_info = []
    for f in snippet.static_findings:
        static_info.append(
            {
                "type": f.vulnerability_type,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "severity": f.severity.value,
                "description": f.description,
            }
        )

    system_content = (
        "Eres un analista experto en seguridad de software. "
        "Tu tarea es revisar fragmentos de código fuente y detectar vulnerabilidades "
        "de seguridad de aplicaciones web (inyección SQL, XSS, control de acceso, "
        "manejo inseguro de datos sensibles, etc.). "
        "Debes responder EXCLUSIVAMENTE en JSON válido, sin texto adicional."
    )

    user_content = {
        "language": snippet.language,
        "file_path": snippet.file_path,
        "start_line": snippet.start_line,
        "end_line": snippet.end_line,
        "code": snippet.code,
        "static_suspicions": static_info,
        "instructions": (
            "Analiza el código y devuelve un objeto JSON con la forma:\n"
            "{\n"
            '  "vulnerabilities": [\n'
            "    {\n"
            '      "is_vulnerability": true/false,\n'
            '      "vulnerability_type": "string",\n'
            '      "cwe_id": "string or null",\n'
            '      "severity": "low|medium|high|critical",\n'
            '      "start_line": int,\n'
            '      "end_line": int,\n'
            '      "description": "string",\n'
            '      "recommendation": "string",\n'
            '      "confidence": float (0.0-1.0)\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "Incluye solo vulnerabilidades reales o altamente probables. "
            "Si no encuentras nada, devuelve vulnerabilities: []."
        ),
    }

    return {
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": str(user_content)},
        ]
    }
