from __future__ import annotations
import hashlib
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain, privacy_for

class AudioHandler(FormatHandler):
    formats=("mp3","flac","ogg","wav")
    def scan(self,path):
        findings=[];warnings=[]
        try:
            from mutagen import File
            obj=File(path,easy=False)
            if obj is None: raise ValueError("Unsupported audio structure")
            tags=getattr(obj,"tags",None)
            if tags:
                for key,val in list(tags.items())[:1000]:
                    text=str(val)
                    category="audio metadata"
                    if key.startswith(("PRIV","UFID")): category="unique/private identifier"
                    findings.append(Finding(str(key),str(key),text[:16384],"audio tag",category,privacy_for(str(key),text),Confidence.CONFIRMED,explain(str(key)),True))
            warnings.append("Cover artwork is metadata-like but may be meaningful user content; DataBreaker does not remove embedded artwork by default.")
            # Hash audio payload heuristically: full file is used when frame-aware hashing is unavailable.
            return findings,warnings,hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception as exc:return findings,[f"Audio parser warning: {exc}"],hashlib.sha256(path.read_bytes()).hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        destination.write_bytes(source.read_bytes())
        from mutagen import File
        obj=File(destination,easy=False)
        if obj is None: raise ValueError("Unsupported audio structure")
        obj.delete();
        if hasattr(obj,"save"): obj.save()
        return ["Audio tags were removed without transcoding the audio stream; embedded artwork behavior depends on the container and is verified by rescan."]
    def validate(self,path):
        try:
            from mutagen import File
            return (File(path,easy=False) is not None,"Audio container parsed by Mutagen")
        except Exception as exc:return False,str(exc)
