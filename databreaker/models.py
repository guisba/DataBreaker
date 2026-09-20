from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    POSSIBLE = "possible"
    WEAK = "weak"
    UNKNOWN = "unknown"


class PrivacyImpact(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    STRUCTURAL = "structural"
    UNKNOWN = "unknown"


class CleanMode(str, Enum):
    SAFE = "safe"
    DEEP = "deep"
    EVERYTHING = "everything"


class NormalizationProfile(str, Enum):
    MINIMAL = "minimal"
    GENERIC = "generic"
    COMPATIBILITY = "compatibility"
    CUSTOM = "custom"


@dataclass(slots=True)
class Finding:
    name: str
    raw_name: str
    value: Any
    source: str
    category: str
    privacy_impact: PrivacyImpact = PrivacyImpact.LOW
    confidence: Confidence = Confidence.CONFIRMED
    explanation: str = ""
    removable: bool = False
    removal_risk: str = "none"
    cryptographically_signed: bool = False
    evidence: list[str] = field(default_factory=list)
    unknown: bool = False
    signature_status: str = "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["privacy_impact"] = self.privacy_impact.value
        data["confidence"] = self.confidence.value
        return data


@dataclass(slots=True)
class FileIdentity:
    filename: str
    size: int
    mime: str
    format: str
    sha256: str
    content_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    identity: FileIdentity
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    capabilities: dict[str, bool] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings,
            "capabilities": self.capabilities,
            "validation": self.validation,
        }


@dataclass(slots=True)
class DiffResult:
    removed: list[dict[str, Any]] = field(default_factory=list)
    retained: list[dict[str, Any]] = field(default_factory=list)
    normalized: list[dict[str, Any]] = field(default_factory=list)
    remaining_sensitive: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CleanResult:
    original: ScanResult
    sanitized: ScanResult
    diff: DiffResult
    output_path: str
    mode: CleanMode
    profile: NormalizationProfile
    validation_ok: bool
    synthetic_fields: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original.to_dict(),
            "sanitized": self.sanitized.to_dict(),
            "diff": self.diff.to_dict(),
            "mode": self.mode.value,
            "profile": self.profile.value,
            "validation_ok": self.validation_ok,
            "synthetic_fields": self.synthetic_fields,
            "warnings": self.warnings,
        }
