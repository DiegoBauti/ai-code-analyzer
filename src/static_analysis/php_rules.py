
import re
from typing import List
from ..core.models import Finding, Severity, FindingSource
import uuid


class PHPSecurityAnalyzer:


    def __init__(self, file_path: str, code: str):
        self.file_path = file_path
        self.code = code
        self.findings: List[Finding] = []

    def _add_finding(
            self,
            start_line: int,
            end_line: int,
            vulnerability_type: str,
            description: str,
            recommendation: str,
            severity: Severity,
            cwe_id: str = None,
            confidence: float = 0.7,
            evidence: dict = None
    ):
        self.findings.append(
            Finding(
                id=str(uuid.uuid4()),
                file_path=self.file_path,
                start_line=start_line,
                end_line=end_line,
                vulnerability_type=vulnerability_type,
                cwe_id=cwe_id,
                severity=severity,
                description=description,
                recommendation=recommendation,
                confidence=confidence,
                source=FindingSource.STATIC,
                raw_evidence=evidence or {}
            )
        )

    def _get_line_number(self, match_start: int) -> tuple:
        start_line = self.code[:match_start].count("\n") + 1
        end_line = start_line
        return start_line, end_line

    def check_sql_injection(self):

        patterns = [
            (r'(mysqli?_query|pg_query|sqlite_query)\s*\([^)]*\$[^)]*\)',
             "Direct variable in database query", 0.8),

            (r'\$\w+\s*=\s*["\']SELECT.*?\$',
             "Variable concatenation in SELECT", 0.7),
            (r'\$\w+\s*=\s*["\']INSERT.*?\$',
             "Variable concatenation in INSERT", 0.7),
            (r'\$\w+\s*=\s*["\']UPDATE.*?\$',
             "Variable concatenation in UPDATE", 0.7),
            (r'\$\w+\s*=\s*["\']DELETE.*?\$',
             "Variable concatenation in DELETE", 0.7),

            (r'(mysqli?_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[',
             "Superglobal variable in query without sanitization", 0.9),
        ]

        for pattern, desc, conf in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE | re.MULTILINE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="SQL Injection",
                    description=f"Posible SQL Injection: {desc}",
                    recommendation="Use prepared statements con bind_param() o PDO con placeholders. Nunca concatene variables directamente en queries SQL.",
                    severity=Severity.CRITICAL,
                    cwe_id="CWE-89",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def check_xss(self):

        patterns = [
            (r'echo\s+\$_(GET|POST|REQUEST|COOKIE)\[',
             "Direct echo of user input", 0.9),
            (r'print\s+\$_(GET|POST|REQUEST|COOKIE)\[',
             "Direct print of user input", 0.9),

            (r'<\?=\s*\$_(GET|POST|REQUEST|COOKIE)\[',
             "Short echo tag with user input", 0.9),

            (r'<(input|textarea|div|span|p|a|title)[^>]*value\s*=\s*["\']?\$\w+',
             "Variable in HTML attribute without escaping", 0.6),

            (r'<script[^>]*>.*?\$\w+',
             "PHP variable in JavaScript context", 0.7),
        ]

        for pattern, desc, conf in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    description=f"Posible XSS: {desc}",
                    recommendation="Sanitice toda entrada de usuario usando htmlspecialchars($var, ENT_QUOTES, 'UTF-8') antes de mostrarla. Para contextos JavaScript use json_encode().",
                    severity=Severity.HIGH,
                    cwe_id="CWE-79",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def check_command_injection(self):

        dangerous_functions = [
            ('exec', 0.9),
            ('shell_exec', 0.9),
            ('system', 0.9),
            ('passthru', 0.9),
            ('popen', 0.8),
            ('proc_open', 0.8),
            ('pcntl_exec', 0.9),
            ('eval', 0.95),
        ]

        for func, conf in dangerous_functions:
            pattern = rf'{func}\s*\([^)]*\$[^)]*\)'
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())

                severity = Severity.CRITICAL if func in ['exec', 'shell_exec', 'system', 'eval'] else Severity.HIGH

                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Command Injection" if func != 'eval' else "Code Injection",
                    description=f"Uso de función peligrosa '{func}()' con variables no sanitizadas",
                    recommendation=f"Evite usar {func}(). Si es necesario, valide y sanitice la entrada usando escapeshellcmd() y escapeshellarg(). Considere alternativas más seguras.",
                    severity=severity,
                    cwe_id="CWE-78" if func != 'eval' else "CWE-94",
                    confidence=conf,
                    evidence={"function": func, "code": match.group(0)[:100]}
                )

        pattern = r'`[^`]*\$[^`]*`'
        for match in re.finditer(pattern, self.code):
            start_line, end_line = self._get_line_number(match.start())
            self._add_finding(
                start_line=start_line,
                end_line=end_line,
                vulnerability_type="Command Injection",
                description="Uso de backticks para ejecución de comandos con variables",
                recommendation="No use backticks. Use funciones seguras o valide la entrada.",
                severity=Severity.CRITICAL,
                cwe_id="CWE-78",
                confidence=0.9,
                evidence={"code": match.group(0)[:100]}
            )

    def check_file_inclusion(self):

        patterns = [
            (r'include\s*\([^)]*\$_(GET|POST|REQUEST)\[', "include with user input", 0.95),
            (r'require\s*\([^)]*\$_(GET|POST|REQUEST)\[', "require with user input", 0.95),
            (r'include_once\s*\([^)]*\$_(GET|POST|REQUEST)\[', "include_once with user input", 0.95),
            (r'require_once\s*\([^)]*\$_(GET|POST|REQUEST)\[', "require_once with user input", 0.95),
        ]

        for pattern, desc, conf in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Local/Remote File Inclusion",
                    description=f"Posible LFI/RFI: {desc}",
                    recommendation="NUNCA use entrada del usuario en include/require. Implemente un whitelist de archivos permitidos y use un mapeo indirecto (ej: switch/case).",
                    severity=Severity.CRITICAL,
                    cwe_id="CWE-98",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def check_path_traversal(self):

        file_functions = [
            ('file_get_contents', 0.8),
            ('fopen', 0.8),
            ('readfile', 0.8),
            ('file', 0.7),
            ('unlink', 0.9),
            ('copy', 0.8),
            ('rename', 0.8),
        ]

        for func, conf in file_functions:
            pattern = rf'{func}\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\['
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Path Traversal",
                    description=f"Posible Path Traversal en {func}() con entrada de usuario",
                    recommendation="Valide y sanitice rutas de archivo. Use basename() para extraer solo el nombre, realpath() para resolver paths, y verifique que el path resultante esté dentro del directorio permitido.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-22",
                    confidence=conf,
                    evidence={"function": func, "code": match.group(0)[:100]}
                )

    def check_weak_crypto(self):

        patterns = [
            (r'\bmd5\s*\(', "MD5", "MD5 es criptográficamente inseguro", 0.9, Severity.MEDIUM),
            (r'\bsha1\s*\(', "SHA1", "SHA1 es criptográficamente inseguro", 0.9, Severity.MEDIUM),
            (r'\bmcrypt_', "mcrypt", "mcrypt está deprecado desde PHP 7.1", 0.95, Severity.HIGH),
            (r'\brand\s*\(', "rand()", "rand() no es criptográficamente seguro", 0.8, Severity.LOW),
            (r'\bmt_rand\s*\(', "mt_rand()", "mt_rand() no es criptográficamente seguro", 0.8, Severity.LOW),
        ]

        for pattern, name, desc, conf, sev in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())

                if name in ["MD5", "SHA1"]:
                    rec = "Use password_hash() con PASSWORD_BCRYPT o PASSWORD_ARGON2ID para passwords. Para hashing use SHA-256 o superior."
                elif name == "mcrypt":
                    rec = "Use OpenSSL (openssl_encrypt/openssl_decrypt) o libsodium (sodium_crypto_secretbox)."
                else:
                    rec = "Use random_bytes() o random_int() para generar valores criptográficamente seguros."

                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Weak Cryptography",
                    description=f"Uso de {name}: {desc}",
                    recommendation=rec,
                    severity=sev,
                    cwe_id="CWE-327",
                    confidence=conf,
                    evidence={"function": name, "code": match.group(0)[:100]}
                )

    def check_insecure_deserialization(self):

        pattern = r'unserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\['

        for match in re.finditer(pattern, self.code, re.IGNORECASE):
            start_line, end_line = self._get_line_number(match.start())
            self._add_finding(
                start_line=start_line,
                end_line=end_line,
                vulnerability_type="Insecure Deserialization",
                description="unserialize() con datos del usuario puede llevar a Remote Code Execution",
                recommendation="NUNCA use unserialize() con datos no confiables. Use JSON (json_decode) en su lugar. Si debe deserializar, implemente validación estricta de clases permitidas usando allowed_classes.",
                severity=Severity.CRITICAL,
                cwe_id="CWE-502",
                confidence=0.95,
                evidence={"code": match.group(0)[:100]}
            )

    def check_open_redirect(self):

        patterns = [
            (r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(GET|POST|REQUEST)\[',
             "header Location with concatenated user input", 0.85),
            (r'header\s*\(\s*["\']Location:\s*\$_(GET|POST|REQUEST)\[',
             "header Location with direct user input", 0.9),
        ]

        for pattern, desc, conf in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Open Redirect",
                    description=f"Posible Open Redirect: {desc}",
                    recommendation="Valide URLs de redirección contra un whitelist de dominios permitidos. Use rutas relativas cuando sea posible. Verifique que la URL comience con '/' o pertenezca a su dominio.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-601",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def check_authentication_issues(self):

        patterns = [
            (r'\$_SESSION\[["\']user["\']?\]\s*=.*?(?!session_regenerate_id)',
             "Session assignment without session_regenerate_id", 0.6, Severity.MEDIUM),

            (r'if\s*\(\s*\$_POST\[["\']pass',
             "Direct password comparison", 0.5, Severity.HIGH),
        ]

        for pattern, desc, conf, sev in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE | re.DOTALL):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Authentication Weakness",
                    description=f"Problema de autenticación: {desc}",
                    recommendation="Siempre use session_regenerate_id(true) después de login. Use password_hash() y password_verify() para passwords. Implemente rate limiting y bloqueo de cuenta.",
                    severity=sev,
                    cwe_id="CWE-287",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def analyze(self) -> List[Finding]:
        self.check_sql_injection()
        self.check_xss()
        self.check_command_injection()
        self.check_file_inclusion()
        self.check_path_traversal()
        self.check_weak_crypto()
        self.check_insecure_deserialization()
        self.check_open_redirect()
        self.check_authentication_issues()

        return self.findings


def analyze_php_file(file_path: str, code: str) -> List[Finding]:

    analyzer = PHPSecurityAnalyzer(file_path, code)
    return analyzer.analyze()