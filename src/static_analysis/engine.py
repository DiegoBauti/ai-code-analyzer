
from pathlib import Path
from typing import List
from ..core.models import Finding
from ..core.config import Config
from .php_rules import analyze_php_file
from .generic_patterns import analyze_generic


def run_static_analysis(file_path: str, config: Config = None) -> List[Finding]:

    if config is None:
        config = Config.load()

    all_findings: List[Finding] = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            print(f" Error leyendo {file_path}: {e}")
            return all_findings
    except Exception as e:
        print(f" Error leyendo {file_path}: {e}")
        return all_findings

    ext = Path(file_path).suffix.lower()
    language = _detect_language(ext)

    enable_py = config.get("static_analysis", "enable_python_rules", default=True)
    enable_php = config.get("static_analysis", "enable_php_rules", default=True)
    enable_js = config.get("static_analysis", "enable_javascript_rules", default=False)
    enable_gen = config.get("static_analysis", "enable_generic_patterns", default=True)

    if enable_php and language == "php":
        all_findings.extend(analyze_php_file(file_path, content))

    if enable_gen:
        all_findings.extend(analyze_generic(file_path, content))

    return all_findings


def _detect_language(extension: str) -> str:

    language_map = {
        '.py': 'python',
        '.pyw': 'python',
        '.php': 'php',
        '.phtml': 'php',
        '.inc': 'php',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rb': 'ruby',
        '.rs': 'rust',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cs': 'csharp',
    }

    return language_map.get(extension.lower(), 'unknown')


def run_static_analysis_batch(file_paths: List[str], config: Config = None) -> List[Finding]:

    if config is None:
        config = Config.load()

    all_findings: List[Finding] = []

    for file_path in file_paths:
        findings = run_static_analysis(file_path, config)
        all_findings.extend(findings)

    return all_findings