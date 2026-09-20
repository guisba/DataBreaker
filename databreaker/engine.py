from __future__ import annotations
import hashlib, json, os, shutil
from pathlib import Path
from .detector import detect
from .fingerprint import derive_origin_findings
from .external import exiftool_findings
from .models import CleanMode, CleanResult, DiffResult, FileIdentity, NormalizationProfile, ScanResult
from .security import LIMITS, safe_filename
from .handlers.jpeg import JPEGHandler
from .handlers.png import PNGHandler
from .handlers.webp import WebPHandler
from .handlers.svg import SVGHandler
from .handlers.ooxml import OOXMLHandler
from .handlers.archive import ArchiveHandler
from .handlers.pdf import PDFHandler
from .handlers.audio import AudioHandler
from .handlers.iso_bmff import ISOBMFFHandler
from .handlers.generic import UnknownHandler

HANDLERS=[JPEGHandler(),PNGHandler(),WebPHandler(),SVGHandler(),OOXMLHandler(),ArchiveHandler(),PDFHandler(),AudioHandler(),ISOBMFFHandler(),UnknownHandler()]


def _handler(fmt):
    for h in HANDLERS:
        if fmt in h.formats:return h
    return UnknownHandler()


def scan_file(path: Path, display_name: str | None=None) -> ScanResult:
    if path.stat().st_size>LIMITS.max_file_bytes: raise ValueError("File exceeds size limit")
    d=detect(path); h=_handler(d.format)
    findings,warnings,content_hash=h.scan(path)
    extra, extra_warnings = exiftool_findings(path)
    existing={(f.raw_name,str(f.value),f.source) for f in findings}
    findings.extend(f for f in extra if (f.raw_name,str(f.value),f.source) not in existing)
    warnings.extend(extra_warnings)
    findings.extend(derive_origin_findings(findings))
    ok,msg=h.validate(path)
    identity=FileIdentity(display_name or path.name,path.stat().st_size,d.mime,d.format,hashlib.sha256(path.read_bytes()).hexdigest(),content_hash)
    clean_supported=h.supports_cleaning() and d.format not in {"tar","7z","heif","avif","matroska","unknown"}
    return ScanResult(identity,findings,warnings,{"clean":clean_supported,"lossless_content_expected":d.format in {"jpeg","png","webp","zip","docx","xlsx","pptx","mp3","flac","ogg","wav","mp4","mov","m4a"}}, {"ok":ok,"message":msg})


def diff_results(before: ScanResult, after: ScanResult) -> DiffResult:
    def key(f):return (f.raw_name,str(f.value),f.source)
    def identity_key(f):return (f.raw_name,f.source)
    b={key(f):f for f in before.findings}; a={key(f):f for f in after.findings}
    removed=[f.to_dict() for k,f in b.items() if k not in a]
    retained=[f.to_dict() for k,f in b.items() if k in a]
    before_by_identity={identity_key(f):f for f in before.findings}
    after_by_identity={identity_key(f):f for f in after.findings}
    normalized=[]
    for ident, old in before_by_identity.items():
        new=after_by_identity.get(ident)
        if new is not None and str(old.value)!=str(new.value):
            normalized.append({"name":old.name,"raw_name":old.raw_name,"source":old.source,"before":old.value,"after":new.value,"synthetic":True})
    remaining=[f.to_dict() for f in after.findings if f.privacy_impact.value in {"critical","high"}]
    warnings=[]
    if remaining:warnings.append("Potentially identifying information remains after cleaning.")
    return DiffResult(removed,retained,normalized,remaining,warnings)


def clean_file(source: Path, output_dir: Path, mode: CleanMode, profile: NormalizationProfile, display_name: str | None=None, options: dict[str, bool] | None=None) -> CleanResult:
    before=scan_file(source,display_name); h=_handler(before.identity.format)
    if not before.capabilities.get("clean",False): raise ValueError(f"Cleaning is not supported for {before.identity.format}")
    name=safe_filename(display_name or source.name); out=output_dir/f"{Path(name).stem}.databreaker{Path(name).suffix}"
    warnings=h.clean(source,out,mode,profile,options)
    ok,msg=h.validate(out)
    if not ok:
        out.unlink(missing_ok=True); raise ValueError(f"Sanitized output failed validation: {msg}")
    after=scan_file(out,out.name); diff=diff_results(before,after)
    if before.identity.content_sha256 and after.identity.content_sha256 and before.identity.content_sha256!=after.identity.content_sha256:
        if before.identity.format in {"jpeg","png","webp","zip","docx","xlsx","pptx"}:
            warnings.append("Primary-content hash changed unexpectedly for a format where metadata-only rewriting should preserve content semantics. Review before use.")
    targeted=[f for f in before.findings if f.removable and (mode!=CleanMode.SAFE or f.privacy_impact.value in {"critical","high","medium"})]
    remaining_keys={(f.raw_name,str(f.value)) for f in after.findings}
    not_removed=[f for f in targeted if (f.raw_name,str(f.value)) in remaining_keys]
    if not_removed:warnings.append(f"{len(not_removed)} targeted metadata finding(s) remain after verification.")
    validation_ok=ok and not any(f.privacy_impact.value=="critical" for f in after.findings if f.removable)
    synthetic_fields=diff.normalized if profile in (NormalizationProfile.GENERIC,NormalizationProfile.CUSTOM,NormalizationProfile.MINIMAL) else []
    return CleanResult(before,after,diff,str(out),mode,profile,validation_ok,synthetic_fields,warnings+diff.warnings)
