"""Atomic, fail-closed writers for every file the pipeline publishes.

Three guarantees live here so no writer has to reinvent them:

* Atomic replace. Content goes to a temp file in the destination directory,
  is fsynced, then ``os.replace``d over the target. A crash or exception
  mid-write leaves the previous file byte-identical.
* Deterministic gzip. Shards are gzipped with a fixed mtime and no filename
  header, so identical content produces identical bytes and no new git blob.
* Reference DB floor. A reference database refuses to overwrite an existing
  non-empty file when the new record count is under half of the old one.
  An upstream outage that parses to ``{}`` fails the run instead of
  publishing an empty file. Growth is always allowed.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence, Tuple

# Refuse to replace an existing non-empty reference DB when the new count is
# under this fraction of the existing count (ISA Decisions 2026-09-26 11:40).
REFERENCE_DB_FLOOR = 0.5

PathLike = str | os.PathLike[str]


class DataFloorError(RuntimeError):
    """A reference DB write was refused because the new data shrank too far."""


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_temp(path: Path, data: bytes) -> Path:
    """Write ``data`` to a fsynced temp file next to ``path``; return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def atomic_write_bytes(path: PathLike, data: bytes) -> None:
    """Atomically replace ``path`` with ``data``."""
    target = Path(path)
    tmp = _write_temp(target, data)
    try:
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_dir(target.parent)


def atomic_write_text(path: PathLike, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: PathLike, obj: Any, **dump_kwargs: Any) -> None:
    """Serialize fully in memory first, then atomically replace ``path``."""
    atomic_write_text(path, json.dumps(obj, **dump_kwargs))


def _backup(target: Path) -> Optional[Path]:
    """Keep the current version of ``target`` at a sibling path, or return
    None when there is none. A hard link costs no copy; copy2 is the fallback
    for filesystems that refuse links."""
    if not target.exists():
        return None
    backup = target.parent / f".{target.name}.{uuid.uuid4().hex}.bak"
    try:
        os.link(target, backup)
    except OSError:
        shutil.copy2(target, backup)
    return backup


def atomic_replace_many(items: Sequence[Tuple[PathLike, bytes]]) -> None:
    """Publish several files so a failure cannot leave a mix of old and new.

    Every temp file is written and fsynced before any target is replaced. A
    failure while writing temps leaves every target untouched. Before the
    replace loop each existing target is kept as a sibling backup; if any
    replace fails, every target already replaced is restored from its backup
    (or removed, if it did not exist before), temps and backups are removed,
    and the error is re-raised.

    This covers an exception, not a hard kill between two replaces. The
    publish-level guarantee also comes from the data workflows committing
    only when the run exits 0, so a half-replaced set never reaches main.
    """
    temps: list[Tuple[Path, Path]] = []
    try:
        for path, data in items:
            target = Path(path)
            temps.append((_write_temp(target, data), target))
    except BaseException:
        for tmp, _ in temps:
            tmp.unlink(missing_ok=True)
        raise

    backups: list[Optional[Path]] = []
    try:
        for _, target in temps:
            backups.append(_backup(target))
    except BaseException:
        for tmp, _ in temps:
            tmp.unlink(missing_ok=True)
        for b in backups:
            if b is not None:
                b.unlink(missing_ok=True)
        raise

    done = 0
    try:
        for tmp, target in temps:
            os.replace(tmp, target)
            done += 1
    except BaseException:
        for i in range(done):
            target = temps[i][1]
            backup = backups[i]
            if backup is not None:
                os.replace(backup, target)
            else:
                target.unlink(missing_ok=True)
        for tmp, _ in temps:
            tmp.unlink(missing_ok=True)
        for b in backups:
            if b is not None:
                b.unlink(missing_ok=True)
        raise

    for b in backups:
        if b is not None:
            b.unlink(missing_ok=True)
    for parent in {t.parent for _, t in temps}:
        _fsync_dir(parent)


def deterministic_gzip(data: bytes) -> bytes:
    """Gzip ``data`` with a fixed header (mtime 0, no filename)."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def jsonl_bytes(records: Iterable[Tuple[str, Any]]) -> bytes:
    """Render ``(key, value)`` pairs as JSONL lines ``{key: value}``."""
    return "".join(json.dumps({k: v}) + "\n" for k, v in records).encode("utf-8")


def count_records(data: Any) -> int:
    """Default record count for a reference DB payload."""
    return len(data) if hasattr(data, "__len__") else 0


def count_groups(data: Any) -> int:
    """groups_db.json nests its records under ``groups``."""
    if isinstance(data, dict):
        groups = data.get("groups")
        if isinstance(groups, dict):
            return len(groups)
    return 0


def count_owasp(data: Any) -> int:
    """owasp_db.json nests its records under ``categories``."""
    if isinstance(data, dict):
        cats = data.get("categories")
        if isinstance(cats, dict):
            return len(cats)
    return 0


def _existing_count(path: Path, counter: Callable[[Any], int]) -> Optional[int]:
    """Count records in the file already on disk, or None when absent.

    An existing file that cannot be parsed counts as 0 so a good fetch can
    repair it.
    """
    if not path.exists():
        return None
    try:
        if path.suffix == ".jsonl":
            existing: dict[str, Any] = {}
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        existing.update(json.loads(line))
            return counter(existing)
        with open(path, "r", encoding="utf-8") as f:
            return counter(json.load(f))
    except (OSError, ValueError):
        return 0


def check_floor(
    path: PathLike,
    data: Any,
    counter: Callable[[Any], int] = count_records,
    floor: float = REFERENCE_DB_FLOOR,
) -> int:
    """Raise DataFloorError when ``data`` would shrink ``path`` below the floor.

    Returns the new record count.
    """
    target = Path(path)
    new_count = counter(data)
    old_count = _existing_count(target, counter)
    if new_count == 0:
        raise DataFloorError(
            f"refusing to write {target}: new data has 0 records "
            f"(existing: {old_count if old_count is not None else 'none'})"
        )
    if old_count and new_count < old_count * floor:
        raise DataFloorError(
            f"refusing to write {target}: {new_count} records is under "
            f"{int(floor * 100)}% of the existing {old_count}"
        )
    return new_count


def write_reference_db(
    path: PathLike,
    data: Any,
    counter: Callable[[Any], int] = count_records,
    indent: Optional[int] = 4,
    separators: Optional[Tuple[str, str]] = None,
    ensure_ascii: bool = True,
) -> int:
    """Floor-check then atomically write a reference DB (JSON or JSONL).

    Returns the number of records written.
    """
    target = Path(path)
    count = check_floor(target, data, counter)
    if target.suffix == ".jsonl":
        atomic_write_bytes(target, jsonl_bytes(data.items()))
    else:
        atomic_write_text(
            target,
            json.dumps(data, indent=indent, separators=separators, ensure_ascii=ensure_ascii),
        )
    return count
