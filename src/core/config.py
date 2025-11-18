import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "sast_ai.config.yaml"


class Config:

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self._validate()

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        config_path = Path(path) if path else DEFAULT_CONFIG_PATH

        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                print(f"✓ Configuración cargada desde: {config_path}")
            except yaml.YAMLError as e:
                print(f"⚠ Error parseando YAML: {e}. Usando configuración por defecto.")
                data = cls._get_defaults()
        else:
            print(f"⚠ No se encontró {config_path}. Usando configuración por defecto.")
            data = cls._get_defaults()

        return cls(cls._merge_with_defaults(data))

    @staticmethod
    def _get_defaults() -> Dict[str, Any]:
        return {
            "general": {
                "default_language": "php",
                "max_snippet_lines": 120,
                "use_ai_by_default": True,
                "max_files_per_scan": 200,
            },
            "ai": {
                "enabled": True,
                "provider": "openai",
                "model": "gpt-4o-mini",
                "base_url": "https://api.openai.com/v1/chat/completions",
                "api_key_env": "OPENAI_API_KEY",
                "temperature": 0.0,
                "max_tokens": 2000,
                "timeout": 30,
                "max_retries": 3,
                "cache_enabled": True,
                "cost_limit_usd": 5.0,
            },
            "static_analysis": {
                "enable_php_rules": True,
                "enable_python_rules": True,
                "enable_javascript_rules": False,
                "enable_generic_patterns": True,
                "complexity_threshold": 10,
            },
            "paths": {
                "include_extensions": [".php", ".phtml", ".inc"],
                "exclude_dirs": [
                    ".git", "vendor", "storage", "cache",
                    ".idea", "node_modules", "__pycache__"
                ],
                "exclude_files": ["*.min.js", "*.map"],
            },
            "severity_thresholds": {
                "ai_min_confidence": 0.6,
                "critical_keyword_score": 0.9,
                "high_keyword_score": 0.7,
            },
            "reporting": {
                "formats": ["json"],
                "output_dir": "reports",
                "include_code_snippets": True,
            },
        }

    @staticmethod
    def _merge_with_defaults(data: Dict[str, Any]) -> Dict[str, Any]:
        defaults = Config._get_defaults()

        def deep_merge(base: dict, overlay: dict) -> dict:
            result = base.copy()
            for key, value in overlay.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        return deep_merge(defaults, data)

    def _validate(self):
        if self.get("ai", "enabled"):
            api_key_env = self.get("ai", "api_key_env")
            if not os.getenv(api_key_env):
                print(f"⚠ Advertencia: Variable de entorno {api_key_env} no configurada. La IA estará deshabilitada.")
                self.data["ai"]["enabled"] = False

        conf = self.get("severity_thresholds", "ai_min_confidence")
        if not (0.0 <= conf <= 1.0):
            raise ValueError("ai_min_confidence debe ser entre 0 y 1.")

    def get(self, *keys, default=None) -> Any:
        node: Any = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def get_api_key(self) -> Optional[str]:
        env_var = self.get("ai", "api_key_env")
        return os.getenv(env_var) if env_var else None

    def is_ai_enabled(self) -> bool:
        return self.get("ai", "enabled") and self.get_api_key() is not None

    def should_analyze_file(self, filepath: str) -> bool:

        path = Path(filepath)

        if path.suffix.lower() not in self.get("paths", "include_extensions", default=[]):
            return False

        for d in self.get("paths", "exclude_dirs", default=[]):
            if d in path.parts:
                return False

        for pattern in self.get("paths", "exclude_files", default=[]):
            if path.match(pattern):
                return False

        return True

    def __repr__(self) -> str:
        return f"<Config ai_enabled={self.is_ai_enabled()} extensions={self.get('paths', 'include_extensions')}>"