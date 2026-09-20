from __future__ import annotations

import hashlib
from pathlib import Path

from .base import FormatHandler
from ..explanations import explain, privacy_for
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..security import LIMITS
from ..tiff import parse_tiff
from ..xmp import parse_xmp


class JPEGHandler(FormatHandler):
    formats = ("jpeg",)

    def _segments(self, data: bytes):
        if not data.startswith(b"\xff\xd8"):
            raise ValueError("Invalid JPEG SOI")
        yield (0, 2, 0xD8, b"")
        pos = 2
        while pos < len(data):
            if data[pos] != 0xFF:
                raise ValueError("Invalid JPEG marker stream")
            while pos < len(data) and data[pos] == 0xFF:
                pos += 1
            if pos >= len(data): break
            marker = data[pos]; marker_start = pos - 1; pos += 1
            if marker in (0xD9,):
                yield (marker_start, pos, marker, b""); break
            if marker in range(0xD0,0xD8) or marker == 0x01:
                yield (marker_start, pos, marker, b""); continue
            if pos + 2 > len(data): raise ValueError("Truncated JPEG segment")
            length = int.from_bytes(data[pos:pos+2], "big")
            if length < 2 or pos + length > len(data): raise ValueError("Invalid JPEG segment length")
            end = pos + length
            payload = data[pos+2:end]
            yield (marker_start, end, marker, payload)
            pos = end
            if marker == 0xDA:
                eoi = data.rfind(b"\xff\xd9")
                if eoi < pos: raise ValueError("JPEG missing EOI")
                yield (pos, eoi, -1, data[pos:eoi])
                yield (eoi, eoi+2, 0xD9, b"")
                break

    def scan(self, path: Path):
        data = path.read_bytes(); findings=[]; warnings=[]; content=hashlib.sha256()
        for start,end,marker,payload in self._segments(data):
            if marker in (-1, 0xDA): content.update(data[start:end])
            if marker == 0xE0:
                findings.append(Finding("JFIF", "APP0/JFIF", payload[:16].hex(), "JPEG APP0", "structural metadata", PrivacyImpact.STRUCTURAL, explanation="JFIF compatibility information.", removable=False))
            elif marker == 0xE1:
                if payload.startswith(b"Exif\x00\x00"):
                    for tv in parse_tiff(payload):
                        findings.append(Finding(tv.name,tv.raw_tag,tv.value,f"JPEG APP1/Exif/{tv.location}","image metadata",privacy_for(tv.name,tv.value),Confidence.CONFIRMED,explain(tv.name),True))
                    findings.append(Finding("EXIF block","APP1/Exif",f"{len(payload)} bytes","JPEG APP1","metadata container",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"EXIF metadata container including TIFF IFDs and possible MakerNotes.",True))
                elif b"xmpmeta" in payload[:1024].lower() or payload.startswith(b"http://ns.adobe.com/xap/1.0/"):
                    items, unknown = parse_xmp(payload)
                    for k,v,_ in items[:500]:
                        findings.append(Finding(k,k,v,"JPEG APP1/XMP","XMP metadata",privacy_for(k,v),Confidence.CONFIRMED,explain(k),True))
                    for ns in unknown:
                        findings.append(Finding("Unknown XMP namespace","XMP namespace",ns,"JPEG APP1/XMP","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Unrecognized XMP namespace. Inspect raw metadata before making assumptions.",True,unknown=True))
                else:
                    findings.append(Finding("Unknown APP1 segment","APP1",f"{len(payload)} bytes","JPEG APP1","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"APP1 data that is not recognized as standard EXIF or XMP.",False,"unknown",unknown=True))
            elif marker == 0xED:
                label = "Photoshop IRB / IPTC" if payload.startswith(b"Photoshop 3.0") else "Unknown APP13"
                findings.append(Finding(label,"APP13",f"{len(payload)} bytes","JPEG APP13","image metadata",PrivacyImpact.MEDIUM,Confidence.HIGH,"May contain Photoshop Image Resource Blocks, IPTC IIM, thumbnails, editing information, or application data.",True))
            elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE"):
                findings.append(Finding("ICC profile","APP2/ICC_PROFILE",f"{len(payload)} bytes","JPEG APP2","structural metadata",PrivacyImpact.STRUCTURAL,Confidence.CONFIRMED,explain("ICC profile"),True,"color shift possible"))
            elif marker == 0xEB and (b"JUMBF" in payload[:128] or b"c2pa" in payload.lower()):
                findings.append(Finding("C2PA/JUMBF provenance","APP11/JUMBF","manifest data","JPEG APP11","cryptographic provenance",PrivacyImpact.MEDIUM,Confidence.HIGH,explain("C2PA"),True,"removal invalidates/removes provenance",True,signature_status="present_unverified"))
            elif 0xE0 <= marker <= 0xEF and marker not in (0xE0,0xE1,0xE2,0xED,0xEB):
                findings.append(Finding(f"Unknown APP{marker-0xE0} segment",f"APP{marker-0xE0}",f"{len(payload)} bytes",f"JPEG APP{marker-0xE0}","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Unclassified JPEG application segment.",mode_removable(marker),"unknown",unknown=True))
        return findings,warnings,content.hexdigest()

    def clean(self, source, destination, mode, profile, options=None):
        data=source.read_bytes(); out=bytearray(); warnings=[]
        keep_icc = profile == NormalizationProfile.COMPATIBILITY or (profile == NormalizationProfile.CUSTOM and bool((options or {}).get("preserve_color_profile", True)))
        for start,end,marker,payload in self._segments(data):
            remove=False
            if marker == 0xE1: remove=True
            elif marker == 0xED and mode in (CleanMode.DEEP,CleanMode.EVERYTHING): remove=True
            elif marker == 0xEB and mode == CleanMode.EVERYTHING: remove=True; warnings.append("C2PA/JUMBF provenance was removed; any signed provenance is no longer present/valid.")
            elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE") and mode == CleanMode.EVERYTHING and not keep_icc: remove=True; warnings.append("ICC profile removed; color appearance can vary across viewers.")
            elif 0xE0 <= marker <= 0xEF and marker not in (0xE0,0xE1,0xE2,0xED,0xEB) and mode == CleanMode.EVERYTHING: remove=True
            if not remove: out.extend(data[start:end])
        destination.write_bytes(out)
        return warnings

    def validate(self, path):
        try:
            data=path.read_bytes(); list(self._segments(data));
            return (data.startswith(b"\xff\xd8") and data.rstrip().endswith(b"\xff\xd9"), "JPEG marker stream parsed")
        except Exception as exc: return False,str(exc)


def mode_removable(marker: int) -> bool:
    return marker not in (0xE0,)
