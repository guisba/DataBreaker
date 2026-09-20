from __future__ import annotations

import hashlib, struct
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain
from ..tiff import parse_tiff
from ..xmp import parse_xmp

class WebPHandler(FormatHandler):
    formats=("webp",)
    def _chunks(self,data):
        if len(data)<12 or data[:4]!=b"RIFF" or data[8:12]!=b"WEBP": raise ValueError("Invalid WebP RIFF")
        pos=12
        while pos+8<=len(data):
            typ=data[pos:pos+4]; n=struct.unpack("<I",data[pos+4:pos+8])[0]; end=pos+8+n+(n&1)
            if end>len(data): raise ValueError("Truncated WebP chunk")
            yield pos,end,typ,data[pos+8:pos+8+n]
            pos=end
    def scan(self,path):
        data=path.read_bytes(); findings=[]; warnings=[]; content=hashlib.sha256()
        structural={b"VP8 ",b"VP8L",b"ALPH",b"ANIM",b"ANMF"}
        for s,e,t,p in self._chunks(data):
            if t in structural: content.update(data[s:e])
            if t==b"EXIF":
                for tv in parse_tiff(p): findings.append(Finding(tv.name,tv.raw_tag,tv.value,f"WebP EXIF/{tv.location}","image metadata",explain_impact(tv.name,tv.value),Confidence.CONFIRMED,explain(tv.name),True))
                findings.append(Finding("EXIF block","EXIF",f"{len(p)} bytes","WebP EXIF","metadata container",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"WebP EXIF metadata chunk.",True))
            elif t==b"XMP ":
                items,unknown=parse_xmp(p)
                for k,v,_ in items[:500]: findings.append(Finding(k,k,v,"WebP XMP","XMP metadata",explain_impact(k,v),Confidence.CONFIRMED,explain(k),True))
                for ns in unknown: findings.append(Finding("Unknown XMP namespace","XMP namespace",ns,"WebP XMP","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Unrecognized XMP namespace.",True,unknown=True))
            elif t==b"ICCP": findings.append(Finding("ICC profile","ICCP",f"{len(p)} bytes","WebP ICCP","structural metadata",PrivacyImpact.STRUCTURAL,Confidence.CONFIRMED,explain("ICC profile"),True,"color shift possible"))
            elif t not in structural: findings.append(Finding("Unknown RIFF/WebP chunk",t.decode("latin1","replace"),f"{len(p)} bytes",f"WebP {t.decode('latin1','replace')}","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Unrecognized WebP chunk.",True,"unknown",unknown=True))
        return findings,warnings,content.hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        data=source.read_bytes(); chunks=[]; warnings=[]; keep_icc=profile==NormalizationProfile.COMPATIBILITY or (profile==NormalizationProfile.CUSTOM and bool((options or {}).get("preserve_color_profile",True)))
        for s,e,t,p in self._chunks(data):
            remove=t in (b"EXIF",b"XMP ")
            if t==b"ICCP" and mode==CleanMode.EVERYTHING and not keep_icc: remove=True; warnings.append("ICC profile removed; color rendering can differ.")
            if t not in {b"VP8 ",b"VP8L",b"VP8X",b"ALPH",b"ANIM",b"ANMF",b"EXIF",b"XMP ",b"ICCP"} and mode==CleanMode.EVERYTHING: remove=True
            if not remove: chunks.append((t,p))
        # Clear VP8X metadata feature flags if metadata chunks were removed.
        rebuilt=[]
        present={t for t,_ in chunks}
        for t,p in chunks:
            if t==b"VP8X" and len(p)>=10:
                q=bytearray(p)
                if b"ICCP" not in present: q[0]&=~0x20
                if b"EXIF" not in present: q[0]&=~0x08
                if b"XMP " not in present: q[0]&=~0x04
                p=bytes(q)
            rebuilt.append(t+struct.pack("<I",len(p))+p+(b"\x00" if len(p)&1 else b""))
        body=b"WEBP"+b"".join(rebuilt); destination.write_bytes(b"RIFF"+struct.pack("<I",len(body))+body); return warnings
    def validate(self,path):
        try:list(self._chunks(path.read_bytes()));return True,"WebP RIFF chunks parsed"
        except Exception as exc:return False,str(exc)

def explain_impact(name,value):
    from ..explanations import privacy_for
    return privacy_for(name,value)
