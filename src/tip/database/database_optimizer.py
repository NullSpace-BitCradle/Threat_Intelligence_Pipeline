"""
Database optimizer and JSONL file manager.

Provides utilities for reading/writing JSONL files and basic database operations.
Supports gzip-compressed .jsonl.gz files for GitHub compatibility.
"""
import gzip
import json
import os
import zlib
from typing import Dict, Any, Generator

from tip.utils.atomic_io import atomic_write_bytes, deterministic_gzip, jsonl_bytes


class ShardCorruptError(ValueError):
    """A JSONL shard is malformed or truncated. The message names the file."""


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
        """Read a JSONL file (plain or gzipped) and yield each parsed line.

        Strict: a malformed line or a truncated/corrupt gzip raises
        ShardCorruptError naming the file, instead of being skipped (and then
        silently dropped on the next rewrite) or surfacing later as a bare
        EOFError.
        """
        resolved, is_gz = self._resolve_path(file_path)
        if not os.path.exists(resolved):
            return

        opener = gzip.open if is_gz else open
        lineno = 0
        try:
            with opener(resolved, 'rt', encoding='utf-8') as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as e:
                        raise ShardCorruptError(
                            f"{resolved}: malformed JSON on line {lineno}: {e}"
                        ) from e
                    if not isinstance(record, dict):
                        raise ShardCorruptError(
                            f"{resolved}: line {lineno} is not a JSON object"
                        )
                    yield record
        except (EOFError, gzip.BadGzipFile, zlib.error, UnicodeDecodeError) as e:
            raise ShardCorruptError(
                f"{resolved}: truncated or corrupt file after line {lineno}: {e}"
            ) from e

    def save_jsonl_incremental(self, file_path: str, data: Dict[str, Any]) -> None:
        """Merge ``data`` into a gzipped JSONL shard and publish it atomically.

        The shard is written deterministically (records sorted by key, gzip
        header with fixed mtime and no filename), so re-writing identical
        content yields byte-identical output and no new git blob.
        """
        existing: Dict[str, Any] = {}
        for entry in self.read_jsonl(file_path):
            existing.update(entry)

        existing.update(data)

        # Always write as .jsonl.gz
        gz_path = file_path + '.gz' if not file_path.endswith('.gz') else file_path
        payload = jsonl_bytes(sorted(existing.items()))
        atomic_write_bytes(gz_path, deterministic_gzip(payload))

        # Remove uncompressed version if it exists
        plain_path = file_path if not file_path.endswith('.gz') else file_path[:-3]
        if os.path.exists(plain_path):
            os.remove(plain_path)


_jsonl_manager = None


def get_jsonl_manager() -> JSONLManager:
    global _jsonl_manager
    if _jsonl_manager is None:
        _jsonl_manager = JSONLManager()
    return _jsonl_manager

