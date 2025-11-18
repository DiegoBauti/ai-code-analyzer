import re
from typing import List, Tuple
from ..core.models import Finding, Severity, FindingSource
import uuid


class PHPSecurityAnalyzerImproved:
    def __init__(self, file_path: str, code: str):
        self.file_path = file_path
        self.code = code
        self.findings: List[Finding] = []
        self.lines = code.split('\n')

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

    def _get_line_number(self, match_start: int) -> Tuple[int, int]:
        start_line = self.code[:match_start].count("\n") + 1
        end_line = start_line
        return start_line, end_line

    def _get_context_lines(self, line_num: int, before: int = 3, after: int = 3) -> str:
        start = max(0, line_num - before - 1)
        end = min(len(self.lines), line_num + after)
        return '\n'.join(self.lines[start:end])

    def _has_prepared_statement_context(self, position: int, window: int = 200) -> bool:
        context_start = max(0, position - window)
        context_end = min(len(self.code), position + window)
        context = self.code[context_start:context_end]

        indicators = [
            r'->prepare\s*\(',
            r'->bind_param\s*\(',
            r'->execute\s*\(',
            r'->bindValue\s*\(',
            r'PDO::PARAM_',
        ]

        return any(re.search(indicator, context, re.IGNORECASE) for indicator in indicators)

    def check_sql_injection(self):
        patterns = [
            (r'(mysqli?_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[',
             "Superglobal in query without sanitization", 0.95, Severity.CRITICAL),

            (r'(SELECT|INSERT|UPDATE|DELETE)\s+.*?\$_(GET|POST|REQUEST|COOKIE)\[',
             "Superglobal concatenation in SQL", 0.85, Severity.CRITICAL),

            (r'\$\w+\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["\']?\s*\.\s*\$\w+',
             "Variable concatenation in SQL query", 0.6, Severity.HIGH),
        ]

        for pattern, desc, conf, sev in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE | re.MULTILINE):
                if self._has_prepared_statement_context(match.start()):
                    conf = max(0.3, conf - 0.4)
                    if conf < 0.5:
                        continue

                start_line, end_line = self._get_line_number(match.start())
                context = self._get_context_lines(start_line)

                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="SQL Injection",
                    description=f"Possible SQL Injection: {desc}",
                    recommendation="Use prepared statements with bind_param() or PDO with placeholders. Never concatenate variables directly in SQL queries.",
                    severity=sev,
                    cwe_id="CWE-89",
                    confidence=conf,
                    evidence={
                        "pattern": desc,
                        "code": match.group(0)[:150],
                        "context": context
                    }
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
                    description=f"Possible XSS: {desc}",
                    recommendation="Sanitize all user input using htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before displaying. For JavaScript contexts use json_encode().",
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
                    description=f"Use of dangerous function '{func}()' with unsanitized variables",
                    recommendation=f"Avoid using {func}(). If necessary, validate and sanitize input using escapeshellcmd() and escapeshellarg(). Consider safer alternatives.",
                    severity=severity,
                    cwe_id="CWE-78" if func != 'eval' else "CWE-94",
                    confidence=conf,
                    evidence={"function": func, "code": match.group(0)[:150]}
                )

        pattern = r'`[^`]*\$[^`]*`'
        for match in re.finditer(pattern, self.code):
            start_line, end_line = self._get_line_number(match.start())
            self._add_finding(
                start_line=start_line,
                end_line=end_line,
                vulnerability_type="Command Injection",
                description="Use of backticks for command execution with variables",
                recommendation="Do not use backticks. Use safe functions or validate input with escapeshellarg().",
                severity=Severity.CRITICAL,
                cwe_id="CWE-78",
                confidence=0.9,
                evidence={"code": match.group(0)[:150]}
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
                    description=f"Possible LFI/RFI: {desc}",
                    recommendation="NEVER use user input in include/require. Implement a whitelist of allowed files and use indirect mapping (e.g., switch/case).",
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
                    description=f"Possible Path Traversal in {func}() with user input",
                    recommendation="Validate and sanitize file paths. Use basename() to extract only the filename, realpath() to resolve paths, and verify the resulting path is within the allowed directory.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-22",
                    confidence=conf,
                    evidence={"function": func, "code": match.group(0)[:100]}
                )

    def check_weak_crypto(self):
        patterns = [
            (r'\bmd5\s*\(', "MD5", "MD5 is cryptographically insecure", 0.9, Severity.MEDIUM),
            (r'\bsha1\s*\(', "SHA1", "SHA1 is cryptographically insecure", 0.9, Severity.MEDIUM),
            (r'\bmcrypt_', "mcrypt", "mcrypt is deprecated since PHP 7.1", 0.95, Severity.HIGH),
            (r'\brand\s*\(', "rand()", "rand() is not cryptographically secure", 0.8, Severity.LOW),
            (r'\bmt_rand\s*\(', "mt_rand()", "mt_rand() is not cryptographically secure", 0.8, Severity.LOW),
        ]

        for pattern, name, desc, conf, sev in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                if name in ["MD5", "SHA1"]:
                    rec = "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID for passwords. For hashing use SHA-256 or higher."
                elif name == "mcrypt":
                    rec = "Use OpenSSL (openssl_encrypt/openssl_decrypt) or libsodium (sodium_crypto_secretbox)."
                else:
                    rec = "Use random_bytes() or random_int() to generate cryptographically secure values."

                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Weak Cryptography",
                    description=f"Use of {name}: {desc}",
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
                description="unserialize() with user data can lead to Remote Code Execution",
                recommendation="NEVER use unserialize() with untrusted data. Use JSON (json_decode) instead. If you must deserialize, implement strict validation of allowed classes using allowed_classes.",
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
                    description=f"Possible Open Redirect: {desc}",
                    recommendation="Validate redirect URLs against a whitelist of allowed domains. Use relative paths when possible. Verify that the URL starts with '/' or belongs to your domain.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-601",
                    confidence=conf,
                    evidence={"pattern": desc, "code": match.group(0)[:100]}
                )

    def check_csrf_protection(self):
        form_pattern = r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>'

        for match in re.finditer(form_pattern, self.code, re.IGNORECASE):
            form_start = match.start()
            form_end = self.code.find('</form>', form_start)

            if form_end == -1:
                form_end = min(form_start + 1000, len(self.code))

            form_content = self.code[form_start:form_end]

            csrf_patterns = [
                r'csrf[_-]?token',
                r'_token',
                r'authenticity[_-]?token',
                r'wp_nonce',
                r'<input[^>]*name\s*=\s*["\']token["\']',
            ]

            has_csrf = any(re.search(pattern, form_content, re.IGNORECASE)
                           for pattern in csrf_patterns)

            if not has_csrf:
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Missing CSRF Protection",
                    description="POST form without apparent CSRF protection",
                    recommendation="Implement unique CSRF tokens per session. Use hash_equals() to validate tokens and regenerate after each use.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-352",
                    confidence=0.65,
                    evidence={"code": match.group(0)[:200]}
                )

    def check_xxe_vulnerabilities(self):
        patterns = [
            (r'simplexml_load_(string|file)\s*\([^)]*\$',
             "simplexml with variable input", 0.75),
            (r'new\s+DOMDocument\s*\(\s*\)\s*;[^;]*->load(XML)?',
             "DOMDocument loading XML", 0.7),
            (r'xml_parser_create\s*\(',
             "XML parser without protection", 0.6),
        ]

        for pattern, desc, conf in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE | re.DOTALL):
                context_start = max(0, match.start() - 400)
                context_end = min(len(self.code), match.start() + 400)
                context = self.code[context_start:context_end]

                protection_patterns = [
                    r'libxml_disable_entity_loader\s*\(\s*true',
                    r'LIBXML_NOENT.*false',
                    r'LIBXML_DTDLOAD.*false',
                ]

                has_protection = any(re.search(p, context, re.IGNORECASE)
                                     for p in protection_patterns)

                if not has_protection:
                    start_line, end_line = self._get_line_number(match.start())
                    self._add_finding(
                        start_line=start_line,
                        end_line=end_line,
                        vulnerability_type="XML External Entity (XXE)",
                        description=f"Possible XXE: {desc} without disabling external entities",
                        recommendation="Use libxml_disable_entity_loader(true) before parsing XML. Disable DTD with LIBXML_DTDLOAD | LIBXML_NOENT = false.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-611",
                        confidence=conf,
                        evidence={"pattern": desc, "code": match.group(0)[:150]}
                    )

    def check_information_disclosure(self):
        patterns = [
            (r'\bphpinfo\s*\(\)', "phpinfo()", 0.9, Severity.HIGH,
             "phpinfo() exposes complete server configuration"),
            (r'\bvar_dump\s*\([^)]*\$_(GET|POST|REQUEST|SESSION)',
             "var_dump() of sensitive data", 0.7, Severity.MEDIUM,
             "May expose session or user data"),
            (r'display_errors\s*=\s*["\']?(?:on|1|true)["\']?',
             "display_errors enabled", 0.8, Severity.MEDIUM,
             "Visible errors expose system paths and logic"),
            (r'error_reporting\s*\(\s*E_ALL\s*\)',
             "error_reporting(E_ALL)", 0.5, Severity.LOW,
             "Reporting all errors may expose information"),
        ]

        for pattern, name, conf, sev, desc in patterns:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                start_line, end_line = self._get_line_number(match.start())
                self._add_finding(
                    start_line=start_line,
                    end_line=end_line,
                    vulnerability_type="Information Disclosure",
                    description=f"{name}: {desc}",
                    recommendation="Disable debugging functions in production. Configure display_errors=Off and log_errors=On in php.ini. Use secure logging.",
                    severity=sev,
                    cwe_id="CWE-200",
                    confidence=conf,
                    evidence={"function": name, "code": match.group(0)[:100]}
                )

    def check_ssrf_vulnerabilities(self):
        url_functions = [
            ('file_get_contents', 0.8),
            ('fopen', 0.8),
            ('curl_init', 0.75),
            ('curl_setopt', 0.7),
        ]

        for func, base_conf in url_functions:
            pattern = rf'{func}\s*\([^)]*(?:https?://|\$_(GET|POST|REQUEST))'

            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                context_start = max(0, match.start() - 400)
                context_end = min(len(self.code), match.start() + 200)
                context = self.code[context_start:context_end]

                validation_patterns = [
                    r'filter_var.*FILTER_VALIDATE_URL',
                    r'parse_url.*host.*whitelist',
                    r'in_array.*allowed_domains',
                ]

                has_validation = any(re.search(p, context, re.IGNORECASE)
                                     for p in validation_patterns)

                conf = base_conf if not has_validation else base_conf * 0.5

                if conf >= 0.5:
                    start_line, end_line = self._get_line_number(match.start())
                    self._add_finding(
                        start_line=start_line,
                        end_line=end_line,
                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                        description=f"Possible SSRF using {func}() with potentially user-controlled URL",
                        recommendation="Validate URLs against whitelist of allowed domains. Use parse_url() to verify host. Block private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x).",
                        severity=Severity.HIGH,
                        cwe_id="CWE-918",
                        confidence=conf,
                        evidence={"function": func, "code": match.group(0)[:150]}
                    )

    def check_authentication_issues(self):
        patterns = [
            (r'\$_SESSION\[["\']user["\']?\]\s*=',
             "Session assignment", 0.4, Severity.LOW),
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
                    description=f"Authentication issue: {desc}",
                    recommendation="Always use session_regenerate_id(true) after login. Use password_hash() and password_verify() for passwords. Implement rate limiting and account lockout.",
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
        self.check_csrf_protection()
        self.check_xxe_vulnerabilities()
        self.check_information_disclosure()
        self.check_ssrf_vulnerabilities()
        self.check_authentication_issues()

        return self.findings


def analyze_php_file(file_path: str, code: str) -> List[Finding]:
    analyzer = PHPSecurityAnalyzerImproved(file_path, code)
    return analyzer.analyze()