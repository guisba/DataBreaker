from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .explanations import explain, privacy_for
from .models import Confidence, Finding, PrivacyImpact


def exiftool_findings(path: Path) -> tuple[list[Finding], list[str]]:
    """Optional local enrichment. Never installs or downloads anything."""
    exe = shutil.which("exiftool")
    if not exe:
        return [], []
    cmd = [exe, "-json", "-G4", "-a", "-u", "-s", "-api", "RequestAll=2", str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"ExifTool enrichment unavailable: {exc}"]
    if len(proc.stdout) > 8 * 1024 * 1024:
        return [], ["ExifTool output exceeded the enrichment safety limit and was ignored."]
    try:
        rows = json.loads(proc.stdout.decode("utf-8", "replace"))
        row = rows[0] if rows else {}
    except (json.JSONDecodeError, IndexError, TypeError):
        return [], ["ExifTool returned output that DataBreaker could not parse."]
    ignored = {"SourceFile", "FileSize", "FileModifyDate", "FileAccessDate", "FileInodeChangeDate", "FilePermissions", "FileType", "FileTypeExtension", "MIMEType", "ImageWidth", "ImageHeight", "Megapixels"}
    findings: list[Finding] = []
    for raw_name, value in row.items():
        short = raw_name.split(":", 1)[-1]
        if short in ignored:
            continue
        value_text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        if len(value_text) > 16_384:
            value_text = value_text[:16_384] + "…"
        group = raw_name.split(":", 1)[0].strip("[]") if ":" in raw_name else "ExifTool"
        unknown = "Unknown" in short or "0x" in short
        category = "manufacturer/application metadata" if any(k in group.lower() for k in ("maker", "canon", "nikon", "sony", "apple", "samsung", "google", "motorola", "fuji", "dji", "gopro")) else "extended metadata"
        findings.append(Finding(
            name=short,
            raw_name=raw_name,
            value=value_text,
            source=f"ExifTool/{group}",
            category="unknown/unclassified" if unknown else category,
            privacy_impact=PrivacyImpact.UNKNOWN if unknown else privacy_for(short, value_text),
            confidence=Confidence.UNKNOWN if unknown else Confidence.CONFIRMED,
            explanation="ExifTool exposed an unknown/proprietary tag; DataBreaker does not infer its meaning." if unknown else explain(short),
            removable=False,
            removal_risk="external-tool finding; core cleaner does not claim removal",
            unknown=unknown,
        ))
    warnings = ["ExifTool was detected locally and used for read-only enrichment, including proprietary/unknown tags."]
    if proc.returncode != 0 and proc.stderr:
        warnings.append("ExifTool reported a parser warning; affected fields should be treated cautiously.")
    return findings, warnings
