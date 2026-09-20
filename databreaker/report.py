from __future__ import annotations
import json
from .models import CleanResult, ScanResult


def json_report(obj: ScanResult | CleanResult) -> str:
    payload=obj.to_dict(); payload["report_version"]="1.0"; payload["tool"]="DataBreaker"
    return json.dumps(payload,ensure_ascii=False,indent=2)


def text_report(obj: ScanResult | CleanResult) -> str:
    if isinstance(obj,CleanResult):
        lines=["DataBreaker — Original → Sanitized",f"Mode: {obj.mode.value}",f"Profile: {obj.profile.value}",f"Validation: {'PASS' if obj.validation_ok else 'WARNING'}",f"Removed: {len(obj.diff.removed)}",f"Retained: {len(obj.diff.retained)}",f"Normalized: {len(obj.diff.normalized)}",f"Sensitive remaining: {len(obj.diff.remaining_sensitive)}"]
        lines.extend(f"NORMALIZED: {item.get('name')} | {item.get('before')} -> {item.get('after')}" for item in obj.diff.normalized)
        lines.extend(f"WARNING: {w}" for w in obj.warnings); return "\n".join(lines)+"\n"
    lines=["DataBreaker — Scan report",f"File: {obj.identity.filename}",f"Format: {obj.identity.format}",f"SHA-256: {obj.identity.sha256}",f"Findings: {len(obj.findings)}"]
    for f in obj.findings: lines.append(f"[{f.privacy_impact.value}] {f.name}: {f.value} ({f.source})")
    return "\n".join(lines)+"\n"
