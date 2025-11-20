import os
from typing import List
from .models import FileContext
from .config import Config


def is_excluded_dir(dir_name: str, config: Config) -> bool:

    excluded = config.get("paths", "exclude_dirs", default=[]) or []
    excluded = [d.lower() for d in excluded]
    return dir_name.lower() in excluded


def has_valid_extension(filename: str, config: Config) -> bool:

    exts = config.get("paths", "include_extensions", default=[]) or []
    exts = [ext.lower() for ext in exts]

    filename = filename.lower()
    return any(filename.endswith(ext) for ext in exts)


def _read_file_safely(path: str) -> str:

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(path, "r", encoding="latin-1") as f:
                return f.read()
        except Exception:
            return None
    except Exception:
        return None


def discover_files(root_path: str, language: str, config: Config) -> List[FileContext]:

    file_contexts: List[FileContext] = []

    if not os.path.exists(root_path):
        raise FileNotFoundError(f"El directorio '{root_path}' no existe")

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [
            d for d in dirnames
            if not is_excluded_dir(d, config)
        ]

        for fname in filenames:
            if not has_valid_extension(fname, config):
                continue

            full_path = os.path.join(dirpath, fname)

            content = _read_file_safely(full_path)
            if content is None:
                continue

            file_contexts.append(
                FileContext(
                    path=os.path.abspath(full_path),
                    language=language,
                    content=content
                )
            )

    return file_contexts


def list_source_files(root_path: str) -> List[str]:

    result = []
    for dirpath, _, filenames in os.walk(root_path):
        for fname in filenames:
            result.append(os.path.join(dirpath, fname))
    return result