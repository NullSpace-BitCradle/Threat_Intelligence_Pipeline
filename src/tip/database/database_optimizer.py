"""
Database optimizer and JSONL file manager.

Provides utilities for reading/writing JSONL files and basic database operations.
"""
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Generator


class JSONLManager:
    """Manages JSONL file operations for CVE database files"""

    def read_jsonl(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Read a JSONL file and yield each parsed line"""
        if not os.path.exists(file_path):
            return
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    def save_jsonl_incremental(self, file_path: str, data: Dict[str, Any]):
        """Save data incrementally to a JSONL file, updating existing entries"""
        existing = {}
        if os.path.exists(file_path):
            for entry in self.read_jsonl(file_path):
                existing.update(entry)

        existing.update(data)

        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            for key, value in existing.items():
                f.write(json.dumps({key: value}) + '\n')


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
