from __future__ import annotations

import re
from .models import Confidence, Finding, PrivacyImpact


AI_PATTERNS = [
    (re.compile(r"stable diffusion|automatic1111|a1111", re.I), "Stable Diffusion / AUTOMATIC1111", Confidence.HIGH),
    (re.compile(r"comfyui", re.I), "ComfyUI", Confidence.HIGH),
    (re.compile(r"invokeai", re.I), "InvokeAI", Confidence.HIGH),
    (re.compile(r"midjourney", re.I), "Midjourney", Confidence.POSSIBLE),
    (re.compile(r"firefly", re.I), "Adobe Firefly", Confidence.HIGH),
    (re.compile(r"dall[·-]?e|openai|chatgpt", re.I), "OpenAI", Confidence.POSSIBLE),
    (re.compile(r"imagen|gemini", re.I), "Google AI", Confidence.POSSIBLE),
    (re.compile(r"runway", re.I), "Runway", Confidence.POSSIBLE),
    (re.compile(r"picsart", re.I), "Picsart", Confidence.POSSIBLE),
    (re.compile(r"flux", re.I), "FLUX workflow", Confidence.POSSIBLE),
]

DEVICE_PATTERNS = [
    (re.compile(r"apple|iphone|ipad", re.I), "Apple", "device manufacturer"),
    (re.compile(r"samsung", re.I), "Samsung", "device manufacturer"),
    (re.compile(r"motorola", re.I), "Motorola", "device manufacturer"),
    (re.compile(r"pixel|google", re.I), "Google", "device manufacturer"),
    (re.compile(r"xiaomi|redmi", re.I), "Xiaomi", "device manufacturer"),
    (re.compile(r"huawei", re.I), "Huawei", "device manufacturer"),
    (re.compile(r"sony", re.I), "Sony", "device manufacturer"),
    (re.compile(r"canon", re.I), "Canon", "camera"),
    (re.compile(r"nikon", re.I), "Nikon", "camera"),
    (re.compile(r"fujifilm|fuji", re.I), "Fujifilm", "camera"),
    (re.compile(r"gopro", re.I), "GoPro", "camera"),
    (re.compile(r"dji", re.I), "DJI", "camera"),
]


def derive_origin_findings(findings: list[Finding]) -> list[Finding]:
    derived: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        text = f"{finding.raw_name} {finding.value}"
        for regex, label, confidence in AI_PATTERNS:
            if regex.search(text):
                key = ("AI pipeline", label)
                if key not in seen:
                    seen.add(key)
                    derived.append(Finding(
                        name=label,
                        raw_name="derived.origin.ai",
                        value=label,
                        source=finding.source,
                        category="AI-generation/editing pipeline",
                        privacy_impact=PrivacyImpact.MEDIUM,
                        confidence=confidence,
                        explanation="This is an origin indicator inferred from an embedded generator/software/workflow value; it is not proof by itself.",
                        removable=finding.removable,
                        evidence=[f"{finding.raw_name}={finding.value}"],
                    ))
        for regex, label, category in DEVICE_PATTERNS:
            if regex.search(text):
                key = (category, label)
                if key not in seen:
                    seen.add(key)
                    derived.append(Finding(
                        name=label,
                        raw_name="derived.origin.device",
                        value=label,
                        source=finding.source,
                        category=category,
                        privacy_impact=PrivacyImpact.MEDIUM,
                        confidence=Confidence.POSSIBLE,
                        explanation="Origin indicator inferred from a metadata value. It can be ambiguous unless backed by a dedicated Make/Model field.",
                        removable=finding.removable,
                        evidence=[f"{finding.raw_name}={finding.value}"],
                    ))
    return derived
