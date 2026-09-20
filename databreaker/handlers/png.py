from __future__ import annotations

import binascii, hashlib, struct, zlib
from pathlib import Path
from .base import FormatHandler
from ..explanations import explain, privacy_for
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..tiff import parse_tiff
from ..xmp import parse_xmp

PNG_SIG=b"\x89PNG\r\n\x1a\n"

class PNGHandler(FormatHandler):
    formats=("png",)
    def _chunks(self,data):
        if not data.startswith(PNG_SIG): raise ValueError("Invalid PNG signature")
        pos=8
        while pos+12<=len(data):
            n=struct.unpack(">I",data[pos:pos+4])[0]; typ=data[pos+4:pos+8]; end=pos+12+n
            if end>len(data): raise ValueError("Truncated PNG chunk")
            payload=data[pos+8:pos+8+n]; crc=data[pos+8+n:end]
            if (binascii.crc32(typ+payload)&0xffffffff)!=struct.unpack(">I",crc)[0]: raise ValueError(f"CRC mismatch in {typ!r}")
            yield pos,end,typ,payload
            pos=end
            if typ==b"IEND": break
    def scan(self,path):
        data=path.read_bytes(); findings=[]; warnings=[]; content=hashlib.sha256()
        known={b"IHDR",b"PLTE",b"IDAT",b"IEND",b"tEXt",b"zTXt",b"iTXt",b"eXIf",b"iCCP",b"sRGB",b"gAMA",b"cHRM",b"pHYs",b"tIME",b"bKGD",b"tRNS",b"sBIT",b"hIST",b"sPLT"}
        for s,e,t,p in self._chunks(data):
            if t in (b"IHDR",b"PLTE",b"IDAT",b"IEND",b"tRNS"): content.update(data[s:e])
            if t==b"tEXt":
                k,_,v=p.partition(b"\0"); key=k.decode("latin1","replace"); val=v.decode("latin1","replace")[:16384]
                findings.append(Finding(key,key,val,"PNG tEXt","text metadata",privacy_for(key,val),Confidence.CONFIRMED,explain(key),True))
                findings.extend(self._ai_text_findings(key,val,"PNG tEXt"))
            elif t==b"zTXt":
                k,_,rest=p.partition(b"\0"); key=k.decode("latin1","replace")
                try:
                    dec=zlib.decompressobj(); raw=dec.decompress(rest[1:],1_000_000); val=raw.decode("utf-8","replace")[:16384]
                except Exception: val="<compressed text>"
                findings.append(Finding(key,key,val,"PNG zTXt","text metadata",privacy_for(key,val),Confidence.CONFIRMED,explain(key),True))
                findings.extend(self._ai_text_findings(key,val,"PNG zTXt"))
            elif t==b"iTXt":
                key=p.split(b"\0",1)[0].decode("latin1","replace"); val=p.decode("utf-8","replace")[:16384]
                findings.append(Finding(key,key,val,"PNG iTXt","text metadata",privacy_for(key,val),Confidence.CONFIRMED,explain(key),True))
                findings.extend(self._ai_text_findings(key,val,"PNG iTXt"))
            elif t==b"eXIf":
                for tv in parse_tiff(p): findings.append(Finding(tv.name,tv.raw_tag,tv.value,f"PNG eXIf/{tv.location}","image metadata",privacy_for(tv.name,tv.value),Confidence.CONFIRMED,explain(tv.name),True))
                findings.append(Finding("EXIF block","eXIf",f"{len(p)} bytes","PNG eXIf","metadata container",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"PNG EXIF metadata block.",True))
            elif t==b"iCCP": findings.append(Finding("ICC profile","iCCP",f"{len(p)} bytes","PNG iCCP","structural metadata",PrivacyImpact.STRUCTURAL,Confidence.CONFIRMED,explain("ICC profile"),True,"color shift possible"))
            elif t in (b"caBX",b"c2pa") or b"c2pa" in p[:512].lower(): findings.append(Finding("C2PA/JUMBF provenance",t.decode("latin1"),f"{len(p)} bytes",f"PNG {t.decode('latin1')}","cryptographic provenance",PrivacyImpact.MEDIUM,Confidence.HIGH,explain("C2PA"),True,"removal invalidates/removes provenance",True,signature_status="present_unverified"))
            elif t not in known and t[:1].islower(): findings.append(Finding("Unknown ancillary chunk",t.decode("latin1","replace"),f"{len(p)} bytes",f"PNG {t.decode('latin1','replace')}","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Unrecognized ancillary PNG chunk.",True,"unknown",unknown=True))
        return findings,warnings,content.hexdigest()
    def _ai_text_findings(self,key,val,source):
        out=[]; low=key.lower()
        if low in {"parameters","prompt","workflow"}:
            pipeline="Stable Diffusion-style generation parameters" if low=="parameters" else ("ComfyUI-style embedded prompt/workflow" if low in {"prompt","workflow"} else "AI workflow")
            out.append(Finding(pipeline,key,"present",source,"AI-generation/editing pipeline",PrivacyImpact.MEDIUM,Confidence.HIGH,"The metadata field is commonly used by local AI image workflows. It is strong workflow evidence, but not cryptographic proof of a specific service.",True,evidence=[f"field={key}"]))
            if low=="parameters":
                import re
                for label,pat in [("Seed",r"(?:^|,\s*)Seed:\s*([^,\n]+)"),("Sampler",r"(?:^|,\s*)Sampler:\s*([^,\n]+)"),("Model",r"(?:^|,\s*)Model:\s*([^,\n]+)"),("Model hash",r"(?:^|,\s*)Model hash:\s*([^,\n]+)"),("Steps",r"(?:^|,\s*)Steps:\s*([^,\n]+)")]:
                    m=re.search(pat,val,re.I)
                    if m: out.append(Finding(label,label,m.group(1),source,"embedded workflow information",PrivacyImpact.MEDIUM,Confidence.HIGH,"Generation parameter embedded by the workflow.",True))
        return out
    def clean(self,source,destination,mode,profile,options=None):
        data=source.read_bytes(); out=bytearray(PNG_SIG); warnings=[]
        keep_icc=profile==NormalizationProfile.COMPATIBILITY or (profile==NormalizationProfile.CUSTOM and bool((options or {}).get("preserve_color_profile",True)))
        for s,e,t,p in self._chunks(data):
            remove=t in (b"tEXt",b"zTXt",b"iTXt",b"eXIf")
            if t==b"iCCP" and mode==CleanMode.EVERYTHING and not keep_icc: remove=True; warnings.append("ICC profile removed; color rendering can differ.")
            if (t in (b"caBX",b"c2pa") or b"c2pa" in p[:512].lower()) and mode==CleanMode.EVERYTHING: remove=True; warnings.append("C2PA/JUMBF provenance removed.")
            if t[:1].islower() and t not in {b"tRNS",b"sRGB",b"gAMA",b"cHRM",b"pHYs",b"bKGD",b"sBIT",b"hIST",b"sPLT",b"iCCP",b"tEXt",b"zTXt",b"iTXt",b"eXIf"} and mode==CleanMode.EVERYTHING: remove=True
            if not remove: out.extend(data[s:e])
        destination.write_bytes(out); return warnings
    def validate(self,path):
        try:
            chunks=list(self._chunks(path.read_bytes())); return (bool(chunks) and chunks[-1][2]==b"IEND","PNG chunks and CRCs parsed")
        except Exception as exc:return False,str(exc)
