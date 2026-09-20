from __future__ import annotations

from .models import PrivacyImpact


CRITICAL_TERMS = ("gps", "location", "latitude", "longitude", "serial", "userid", "user id", "owner id", "hostcomputer")
HIGH_TERMS = ("author", "creator", "artist", "company", "organization", "owner", "username", "path", "filename", "machine")
MEDIUM_TERMS = ("software", "producer", "make", "model", "lens", "firmware", "timestamp", "date", "time", "encoder", "generator")


def privacy_for(name: str, value: object = "") -> PrivacyImpact:
    text = f"{name} {value}".lower()
    if any(x in text for x in CRITICAL_TERMS):
        return PrivacyImpact.CRITICAL
    if any(x in text for x in HIGH_TERMS):
        return PrivacyImpact.HIGH
    if any(x in text for x in MEDIUM_TERMS):
        return PrivacyImpact.MEDIUM
    return PrivacyImpact.LOW


def explain(name: str) -> str:
    n = name.lower()
    if "gps" in n or "location" in n or "latitude" in n or "longitude" in n:
        return "Contains geographic information that can reveal where the media was created or edited."
    if "serial" in n:
        return "May contain a persistent device, lens, document, or workflow identifier that can link files together."
    if "software" in n or "producer" in n or "encoder" in n or "generator" in n:
        return "May reveal the application, encoder, service, or version that last wrote this metadata."
    if "make" in n or "manufacturer" in n:
        return "May reveal the manufacturer of the device that created or processed the file."
    if "model" in n:
        return "May reveal a specific device, camera, phone, lens, or software model."
    if "author" in n or "creator" in n or "artist" in n:
        return "May reveal the name or account identity of a person associated with the file."
    if "company" in n or "organization" in n:
        return "May reveal an organization associated with the authoring environment."
    if "path" in n or "filename" in n:
        return "May reveal local filesystem structure, usernames, project names, or source filenames."
    if "time" in n or "date" in n:
        return "May reveal creation or editing chronology and, when offsets are present, timezone information."
    if "c2pa" in n or "content credential" in n or "jumbf" in n:
        return "Cryptographic provenance structure. Rewriting or removing it can invalidate or remove signed provenance."
    if "icc" in n or "color profile" in n:
        return "Color-management data. It is usually not identifying and removing it can change color interpretation."
    if "thumbnail" in n:
        return "Embedded preview data can contain a second copy of visual content and may retain independent metadata."
    return "Non-content information embedded in the file. Its privacy impact depends on the value and surrounding format."
