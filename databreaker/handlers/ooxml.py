from __future__ import annotations
import hashlib, re, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain, privacy_for
from ..security import LIMITS, is_safe_archive_member

SENSITIVE_CORE={"creator","lastModifiedBy","created","modified","lastPrinted","identifier","subject","keywords","category","description"}

class OOXMLHandler(FormatHandler):
    formats=("docx","xlsx","pptx")
    def scan(self,path):
        findings=[]; warnings=[]; content=hashlib.sha256()
        with zipfile.ZipFile(path) as z:
            infos=z.infolist()
            if len(infos)>LIMITS.max_archive_entries: raise ValueError("OOXML entry limit exceeded")
            names=set(z.namelist())
            for name in names:
                if not is_safe_archive_member(name): warnings.append(f"Unsafe package path: {name}")
                if name.startswith("docProps/") and name.endswith(".xml"):
                    try:
                        root=ET.fromstring(z.read(name))
                        for elem in root.iter():
                            local=elem.tag.rsplit("}",1)[-1]
                            text=(elem.text or "").strip()
                            if text:
                                findings.append(Finding(local,elem.tag,text[:16384],name,"OOXML properties",privacy_for(local,text),Confidence.CONFIRMED,explain(local),True))
                    except ET.ParseError: warnings.append(f"Malformed properties XML: {name}")
                if "customXml/" in name: findings.append(Finding("Custom XML part","customXml",name,name,"embedded/custom XML",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Custom XML can contain application data, identifiers, or business metadata. It may also be functional content.",False,"may affect document behavior"))
                if re.search(r"comments\d*\.xml$",name): findings.append(Finding("Comments part","comments",name,name,"document content",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Comments can expose authors and discussion but are user-visible/document content, not silently removed.",False,"content removal"))
                if name.endswith(".xml") and not name.startswith("docProps/"):
                    if z.getinfo(name).file_size <= 4*1024*1024:
                        raw=z.read(name)
                        if b"w:ins" in raw or b"w:del" in raw: findings.append(Finding("Tracked revisions","w:ins/w:del","present",name,"document content",PrivacyImpact.HIGH,Confidence.HIGH,"Tracked changes may contain deleted/revised text and author information; DataBreaker reports but does not silently accept/reject revisions.",False,"content change"))
                        if b'TargetMode="External"' in raw: findings.append(Finding("External relationship","TargetMode=External","present",name,"external links",PrivacyImpact.MEDIUM,Confidence.HIGH,"External relationships can reveal remote URLs or linked resources.",False,"may affect functionality"))
                if not name.startswith("docProps/") and not name.endswith("/") and z.getinfo(name).file_size <= 16*1024*1024:
                    try: content.update(name.encode()+b"\0"+hashlib.sha256(z.read(name)).digest())
                    except Exception: pass
                info=z.getinfo(name)
                if not info.is_dir(): findings.append(Finding("Package member timestamp","timestamp",str(info.date_time),name,"archive metadata",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"OOXML ZIP member modification time; it can reveal when a package part was written.",True))
                if info.extra: findings.append(Finding("ZIP extra fields","extra",info.extra.hex()[:1024],name,"archive metadata",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"OOXML is a ZIP package; extra fields can carry timestamps or host-specific metadata.",True))
            if "docProps/thumbnail.jpeg" in names or "docProps/thumbnail.png" in names: findings.append(Finding("Embedded thumbnail","thumbnail","present","docProps","embedded preview",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,explain("thumbnail"),True,"preview removal"))
        return findings,warnings,content.hexdigest()
    def _sanitize_props(self,raw:bytes,mode:CleanMode):
        root=ET.fromstring(raw)
        for elem in root.iter():
            local=elem.tag.rsplit("}",1)[-1]
            if local in SENSITIVE_CORE or (mode!=CleanMode.SAFE and local.lower() in {"application","appversion","company","manager","template","hyperlinkbase"}):
                elem.text=""
        return ET.tostring(root,encoding="utf-8",xml_declaration=True)
    def clean(self,source,destination,mode,profile,options=None):
        warnings=["Comments, tracked revisions, embedded objects, external links, and custom XML are reported but not silently removed because they can be document content or functionality."]
        with zipfile.ZipFile(source) as zin, zipfile.ZipFile(destination,"w") as zout:
            for info in zin.infolist():
                if not is_safe_archive_member(info.filename): raise ValueError("Unsafe OOXML path")
                data=zin.read(info)
                if info.filename in {"docProps/core.xml","docProps/app.xml","docProps/custom.xml"}:
                    try:data=self._sanitize_props(data,mode)
                    except ET.ParseError: warnings.append(f"Could not sanitize malformed {info.filename}")
                ni=zipfile.ZipInfo(info.filename,date_time=info.date_time if (mode==CleanMode.SAFE or profile==NormalizationProfile.COMPATIBILITY or (profile==NormalizationProfile.CUSTOM and bool((options or {}).get("preserve_archive_timestamps",False)))) else ((2000,1,1,0,0,0) if profile in (NormalizationProfile.GENERIC,NormalizationProfile.CUSTOM) else (1980,1,1,0,0,0)))
                ni.compress_type=info.compress_type; ni.external_attr=info.external_attr
                ni.extra=b"" if mode!=CleanMode.SAFE else info.extra
                zout.writestr(ni,data)
        return warnings
    def validate(self,path):
        try:
            with zipfile.ZipFile(path) as z:
                bad=z.testzip(); names=set(z.namelist()); valid="[Content_Types].xml" in names and "_rels/.rels" in names
                return (bad is None and valid,"OOXML ZIP CRC and package roots validated")
        except Exception as exc:return False,str(exc)
