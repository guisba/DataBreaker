from __future__ import annotations

import json
import shutil
try:
    import subprocess
except (ImportError, OSError):  # Browser/Pyodide environments do not provide OS subprocesses.
    subprocess = None
from pathlib import Path

from .explanations import explain, privacy_for
from .models import Confidence, Finding, PrivacyImpact

FILESYSTEM_FIELDS = {
    "SourceFile", "FileName", "Directory", "FileSize", "FileModifyDate",
    "FileAccessDate", "FileInodeChangeDate", "FilePermissions", "FileCreateDate",
}
STRUCTURAL_FIELDS = {
    "FileType", "FileTypeExtension", "MIMEType", "ImageWidth", "ImageHeight",
    "BitDepth", "ColorType", "Compression", "Filter", "Interlace", "ImageSize",
    "Megapixels", "PDFVersion", "PageCount", "Linearized", "PageMode",
}


def _category(raw_name: str, short: str, group: str) -> str:
    combined = f"{raw_name} {short} {group}".lower()
    if short in FILESYSTEM_FIELDS:
        return "filesystem/runtime metadata"
    if short in STRUCTURAL_FIELDS:
        return "file/structural metadata"
    if any(key in combined for key in ("c2pa", "jumbf", "jumd", "cbor", "claim_generator", "assertion")):
        return "cryptographic provenance"
    if any(key in combined for key in ("gps", "location", "latitude", "longitude", "altitude")):
        return "location metadata"
    if any(key in combined for key in (
        "maker", "canon", "nikon", "sony", "apple", "samsung", "google",
        "motorola", "fuji", "dji", "gopro", "olympus", "pentax", "panasonic",
    )):
        return "manufacturer/application metadata"
    return "extended metadata"


def _explanation(raw_name: str, short: str, group: str, unknown: bool) -> str:
    if short in FILESYSTEM_FIELDS:
        return (
            "Filesystem/runtime attribute reported by ExifTool. For temporary or browser-hosted "
            "copies this may describe the processing environment rather than embedded source metadata."
        )
    if any(key in f"{raw_name} {group}".lower() for key in ("c2pa", "jumbf", "jumd", "cbor")):
        return (
            "Field decoded from C2PA/JUMBF/CBOR provenance by ExifTool. Presence is evidence of a "
            "provenance structure, not independent cryptographic verification."
        )
    if unknown:
        return (
            "ExifTool exposed an unknown/proprietary tag; DataBreaker keeps it visible instead of "
            "discarding a field it cannot interpret."
        )
    return explain(short)


def exiftool_findings(path: Path) -> tuple[list[Finding], list[str]]:
    """Optional local full-inventory enrichment. Never installs or downloads anything."""
    if subprocess is None:
        return [], []
    exe = shutil.which("exiftool")
    if not exe:
        return [], []

    cmd = [
        exe,
        "-json",
        "-a",
        "-u",
        "-G0:4",
        "-s",
        "-ee3",
        "-api",
        "RequestAll=3",
        "-api",
        "LargeFileSupport=1",
        str(path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"ExifTool full inventory unavailable: {exc}"]

    if len(proc.stdout) > 64 * 1024 * 1024:
        return [], ["ExifTool output exceeded the 64 MB inventory safety limit and was ignored."]

    try:
        rows = json.loads(proc.stdout.decode("utf-8", "replace"))
        row = rows[0] if rows else {}
    except (json.JSONDecodeError, IndexError, TypeError):
        return [], ["ExifTool returned full-inventory output that DataBreaker could not parse."]

    findings: list[Finding] = []
    for raw_name, value in row.items():
        parts = str(raw_name).split(":")
        short = parts[-1]
        group = ":".join(parts[:-1]) or "ExifTool"
        unknown = "unknown" in short.lower() or "0x" in short.lower()
        value_text = (
            json.dumps(value, ensure_ascii=False)
            if isinstance(value, (dict, list))
            else str(value)
        )
        if len(value_text) > 16_384:
            value_text = value_text[:16_384] + "…"

        category = _category(str(raw_name), short, group)
        impact = PrivacyImpact.UNKNOWN if unknown else privacy_for(short, value_text)
        if short in STRUCTURAL_FIELDS:
            impact = PrivacyImpact.STRUCTURAL
        if category == "cryptographic provenance" and impact in {PrivacyImpact.LOW, PrivacyImpact.STRUCTURAL}:
            impact = PrivacyImpact.MEDIUM

        provenance = category == "cryptographic provenance"
        findings.append(Finding(
            name=short,
            raw_name=str(raw_name),
            value=value_text,
            source=f"ExifTool/{group}",
            category="unknown/unclassified" if unknown else category,
            privacy_impact=impact,
            confidence=Confidence.UNKNOWN if unknown else Confidence.CONFIRMED,
            explanation=_explanation(str(raw_name), short, group, unknown),
            removable=False,
            removal_risk="full-inventory field; core cleaner only claims removal after native verification",
            cryptographically_signed=provenance and any(
                token in short.lower() for token in ("signature", "ocsp", "tst")
            ),
            evidence=[f"ExifTool tag={raw_name}"],
            unknown=unknown,
            signature_status="present_unverified" if provenance else "not_applicable",
        ))

    warnings = [
        "ExifTool was detected locally and used in full-inventory mode "
        "(-ee3, RequestAll=3, duplicate and unknown tags enabled)."
    ]
    if proc.returncode != 0 and proc.stderr:
        warnings.append("ExifTool reported a parser warning; affected fields should be treated cautiously.")
    return findings, warnings
