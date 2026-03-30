"""
Database optimizer and JSONL file manager.

Provides utilities for reading/writing JSONL files and basic database operations.
Supports gzip-compressed .jsonl.gz files for GitHub compatibility.
"""
import gzip
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Generator


class JSONLManager:
    """Manages JSONL file operations for CVE database files"""

    def _resolve_path(self, file_path: str) -> tuple[str, bool]:
        """Resolve file path, preferring .jsonl.gz over .jsonl.
        Returns (resolved_path, is_gzipped)."""
        gz_path = file_path + '.gz' if not file_path.endswith('.gz') else file_path
        plain_path = file_path[:-3] if file_path.endswith('.gz') else file_path

        if os.path.exists(gz_path):
            return gz_path, True
        if os.path.exists(plain_path):
            return plain_path, False
        # Default to gz for new files
        return gz_path, True

    def read_jsonl(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Read a JSONL file (plain or gzipped) and yield each parsed line"""
        resolved, is_gz = self._resolve_path(file_path)
        if not os.path.exists(resolved):
            return

        opener = gzip.open if is_gz else open
        with opener(resolved, 'rt', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    def save_jsonl_incremental(self, file_path: str, data: Dict[str, Any]):
        """Save data incrementally to a gzipped JSONL file, updating existing entries"""
        existing = {}
        if os.path.exists(file_path) or os.path.exists(file_path + '.gz'):
            for entry in self.read_jsonl(file_path):
                existing.update(entry)

        existing.update(data)

        # Always write as .jsonl.gz
        gz_path = file_path + '.gz' if not file_path.endswith('.gz') else file_path
        Path(gz_path).parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(gz_path, 'wt', encoding='utf-8') as f:
            for key, value in existing.items():
                f.write(json.dumps({key: value}) + '\n')

        # Remove uncompressed version if it exists
        plain_path = file_path if not file_path.endswith('.gz') else file_path[:-3]
        if os.path.exists(plain_path):
            os.remove(plain_path)


class DatabaseOptimizer:
    """Basic database optimization utilities"""

    def __init__(self):
        self.cache = {}

    def get_cached(self, key: str) -> Any:
        return self.cache.get(key)

    def set_cached(self, key: str, value: Any):
        self.cache[key] = value


_jsonl_manager = None
_db_optimizer = None


def get_jsonl_manager() -> JSONLManager:
    global _jsonl_manager
    if _jsonl_manager is None:
        _jsonl_manager = JSONLManager()
    return _jsonl_manager


def get_database_optimizer() -> DatabaseOptimizer:
    global _db_optimizer
    if _db_optimizer is None:
        _db_optimizer = DatabaseOptimizer()
    return _db_optimizer
