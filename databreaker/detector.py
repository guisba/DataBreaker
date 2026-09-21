from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Detection:
    format: str
    mime: str


def detect(path: Path) -> Detection:
    with open(path, "rb") as fh:
        head = fh.read(512)
    suffix = path.suffix.lower()
    if head.startswith(b"\xff\xd8\xff"):
        return Detection("jpeg", "image/jpeg")
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return Detection("png", "image/png")
    if head.startswith((b"GIF87a", b"GIF89a")):
        return Detection("gif", "image/gif")
    if head[:4] in (b"RIFF", b"RIFX") and head[8:12] == b"WEBP":
        return Detection("webp", "image/webp")
    if head.startswith(b"%PDF-"):
        return Detection("pdf", "application/pdf")
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        if suffix in {".docx", ".docm"}:
            return Detection("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if suffix in {".xlsx", ".xlsm"}:
            return Detection("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        if suffix in {".pptx", ".pptm"}:
            return Detection("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
        return Detection("zip", "application/zip")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return Detection("7z", "application/x-7z-compressed")
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"} or suffix in {".heic", ".heif"}:
            return Detection("heif", "image/heif")
        if brand in {b"avif", b"avis"} or suffix == ".avif":
            return Detection("avif", "image/avif")
        if suffix in {".mov", ".qt"} or brand == b"qt  ":
            return Detection("mov", "video/quicktime")
        if suffix in {".m4a", ".m4b"}:
            return Detection("m4a", "audio/mp4")
        if suffix == ".m4v":
            return Detection("m4v", "video/x-m4v")
        return Detection("mp4", "video/mp4")
    if head.startswith(b"ID3") or suffix == ".mp3":
        return Detection("mp3", "audio/mpeg")
    if head.startswith(b"fLaC"):
        return Detection("flac", "audio/flac")
    if head.startswith(b"OggS"):
        return Detection("ogg", "audio/ogg")
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return Detection("wav", "audio/wav")
    if head.startswith(b"\x1aE\xdf\xa3"):
        return Detection("matroska", "video/x-matroska")
    if head.startswith(b"<svg") or (b"<svg" in head and suffix == ".svg"):
        return Detection("svg", "image/svg+xml")
    if len(head) >= 262 and head[257:262] == b"ustar":
        return Detection("tar", "application/x-tar")
    if suffix == ".tar":
        return Detection("tar", "application/x-tar")
    if suffix in {".dng", ".cr2", ".cr3", ".nef", ".arw", ".orf", ".pef", ".raw", ".crw", ".raf", ".rw2"}:
        return Detection("raw", "image/x-raw")
    return Detection("unknown", "application/octet-stream")
