from __future__ import annotations
import hashlib, re, struct
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain, privacy_for

CONTAINER_TYPES={b"moov",b"trak",b"mdia",b"minf",b"stbl",b"udta",b"meta",b"ilst",b"moof",b"traf",b"meco",b"mere",b"iprp",b"ipco"}
PRIVACY_KEYS={
    b"com.apple.quicktime.location.ISO6709":"Location ISO6709",
    b"com.apple.quicktime.make":"Device make",
    b"com.apple.quicktime.model":"Device model",
    b"com.apple.quicktime.software":"Software",
    b"com.apple.quicktime.creationdate":"Creation date",
    b"com.apple.quicktime.author":"Author",
    b"com.apple.quicktime.artist":"Artist",
    b"com.apple.quicktime.hostcomputer":"Host computer",
}

class ISOBMFFHandler(FormatHandler):
    formats=("mp4","mov","m4a","heif","avif")
    def _boxes(self,data,start=0,end=None,depth=0,prefix=""):
        end=len(data) if end is None else min(end,len(data)); pos=start
        while pos+8<=end:
            size=struct.unpack(">I",data[pos:pos+4])[0]; typ=data[pos+4:pos+8]; header=8
            if size==1:
                if pos+16>end: break
                size=struct.unpack(">Q",data[pos+8:pos+16])[0]; header=16
            elif size==0:size=end-pos
            if size<header or pos+size>end: break
            path=f"{prefix}/{typ.decode('latin1','replace')}"
            yield pos,pos+size,typ,path,depth,data[pos+header:pos+size]
            child_start=pos+header
            if typ==b"meta": child_start+=4
            if typ in CONTAINER_TYPES and depth<8:
                yield from self._boxes(data,child_start,pos+size,depth+1,path)
            pos+=size
    def scan(self,path):
        data=path.read_bytes(); findings=[]; warnings=[]; content=hashlib.sha256()
        boxes=list(self._boxes(data))
        if not boxes: return [],["Unable to parse ISO-BMFF boxes"],hashlib.sha256(data).hexdigest()
        for s,e,t,pth,d,p in boxes:
            if t in (b"mdat",b"idat"): content.update(data[s:e])
            if t==b"uuid" and b"c2pa" in p[:1024].lower(): findings.append(Finding("C2PA provenance","uuid",f"{len(p)} bytes",pth,"cryptographic provenance",PrivacyImpact.MEDIUM,Confidence.HIGH,explain("C2PA"),False,"rewrite may invalidate provenance",True,signature_status="present_unverified"))
            if t in (b"XMP_",b"xml ") and (b"xmp" in p[:1024].lower() or b"rdf" in p[:1024].lower()): findings.append(Finding("XMP metadata",t.decode("latin1"),f"{len(p)} bytes",pth,"XMP metadata",PrivacyImpact.MEDIUM,Confidence.HIGH,explain("XMP"),False,"container rewrite required"))
            if t in (b"keys",b"data",b"mean",b"name") or b"com.apple.quicktime" in p:
                sample=p[:32768]
                for key,label in PRIVACY_KEYS.items():
                    if key in sample:
                        findings.append(Finding(label,key.decode(),"present",pth,"QuickTime metadata",privacy_for(label),Confidence.HIGH,explain(label),False,"container rewrite required",evidence=[key.decode()]))
            # iTunes/QuickTime atoms, including the binary ©xyz tag.
            if t in {b"\xa9xyz",b"\xa9too",b"\xa9ART",b"\xa9nam",b"\xa9day",b"\xa9cmt"}:
                raw=t.decode("latin1"); val=p[-8192:].decode("utf-8","replace").strip("\x00")[:4096]
                findings.append(Finding(raw,raw,val,pth,"QuickTime metadata",privacy_for(raw,val),Confidence.HIGH,explain(raw),False,"container rewrite required"))
        if not content.digest_size or not any(t in (b"mdat",b"idat") for _,_,t,_,_,_ in boxes): content.update(data)
        if path.suffix.lower() in {".heic",".heif",".avif"}: warnings.append("HEIF/AVIF structural metadata is inspected conservatively; automatic cleaning is disabled unless a safe rewrite is available.")
        return findings,warnings,content.hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        # Mutagen can safely rewrite common MP4/M4A tags without re-encoding media; HEIF/AVIF is analysis-only.
        if source.suffix.lower() in {".heic",".heif",".avif"}:
            raise ValueError("Automatic HEIF/AVIF cleaning is disabled to avoid destructive container rewrites")
        destination.write_bytes(source.read_bytes())
        try:
            from mutagen.mp4 import MP4
            media=MP4(destination)
            if media.tags is not None:
                media.delete(); media.save()
            return ["QuickTime/MP4 tags were rewritten without transcoding media streams. Embedded provenance or uncommon boxes may remain and are rescanned."]
        except Exception as exc:
            destination.unlink(missing_ok=True)
            raise ValueError(f"MP4/MOV metadata rewrite failed: {exc}") from exc
    def validate(self,path):
        try:
            boxes=list(self._boxes(path.read_bytes())); return (bool(boxes) and boxes[0][2]==b"ftyp","ISO-BMFF box structure parsed")
        except Exception as exc:return False,str(exc)
