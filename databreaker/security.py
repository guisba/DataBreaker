from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecurityLimits:
    max_file_bytes: int = 100 * 1024 * 1024
    max_files: int = 20
    max_metadata_block_bytes: int = 16 * 1024 * 1024
    max_archive_entries: int = 10_000
    max_archive_uncompressed_bytes: int = 512 * 1024 * 1024
    max_archive_ratio: int = 250
    max_recursion_depth: int = 3
    max_text_value: int = 16_384


LIMITS = SecurityLimits()


def safe_filename(name: str) -> str:
    name = Path(name or "file").name
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name[:180] or "file"


def is_safe_archive_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return False
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    return ".." not in parts


def bounded_read(path: Path, max_bytes: int | None = None) -> bytes:
    limit = max_bytes or LIMITS.max_file_bytes
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"File exceeds the configured {limit} byte limit")
    return path.read_bytes()


def atomic_replace_bytes(destination: Path, data: bytes) -> None:
    tmp = destination.with_name(destination.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, destination)
