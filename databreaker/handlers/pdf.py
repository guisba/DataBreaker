from __future__ import annotations
import hashlib, re
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain, privacy_for

class PDFHandler(FormatHandler):
    formats=("pdf",)
    def scan(self,path):
        raw=path.read_bytes(); findings=[]; warnings=[]
        try:
            from pypdf import PdfReader
            reader=PdfReader(path,strict=False)
            meta=reader.metadata or {}
            for k,v in meta.items():
                findings.append(Finding(str(k),str(k),str(v)[:16384],"PDF Info dictionary","PDF metadata",privacy_for(str(k),v),Confidence.CONFIRMED,explain(str(k)),True,"rewriting invalidates signatures"))
            root=reader.trailer.get("/Root",{})
            for key,label,category in [("/Metadata","XMP metadata","XMP metadata"),("/AcroForm","AcroForm","forms"),("/OCProperties","Optional content/layers","structural metadata"),("/Names","Names tree / attachments or JavaScript","embedded structures")]:
                if key in root: findings.append(Finding(label,key,"present","PDF catalog",category,PrivacyImpact.MEDIUM,Confidence.HIGH,explain(label), key=="/Metadata","may affect signatures/behavior"))
            if getattr(reader,"attachments",None): findings.append(Finding("Embedded attachments","/EmbeddedFiles",f"{len(reader.attachments)} names","PDF names tree","document content",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Attachments can carry private files. They are content and are not silently deleted.",False,"content removal"))
            annots=sum(1 for p in reader.pages if "/Annots" in p)
            if annots: findings.append(Finding("Annotations/comments","/Annots",f"present on {annots} pages","PDF pages","document content",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Annotations may contain authors, comments, links, or review history and are not silently removed.",False,"content removal"))
        except Exception as exc:warnings.append(f"PDF parser warning: {exc}")
        patterns=[(rb"/ID\s*\[","Document ID","/ID","unique identifiers"),(rb"/JavaScript\b|/JS\b","JavaScript","/JavaScript","active content"),(rb"/ByteRange\s*\[","Digital signature","/ByteRange","cryptographic provenance"),(rb"/Prev\s+\d+","Incremental update history","/Prev","structural history")]
        for pat,label,rawname,cat in patterns:
            count=len(re.findall(pat,raw))
            if count: findings.append(Finding(label,rawname,f"{count} occurrence(s)","raw PDF structure",cat,PrivacyImpact.HIGH if label in {"Document ID","JavaScript"} else PrivacyImpact.MEDIUM,Confidence.HIGH,explain(label),False,"structural rewrite required",label=="Digital signature",signature_status="present_unverified" if label=="Digital signature" else "not_applicable"))
        return findings,warnings,hashlib.sha256(raw).hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        from pypdf import PdfReader, PdfWriter
        reader=PdfReader(source,strict=False); writer=PdfWriter(); writer.clone_document_from_reader(reader)
        writer.add_metadata({})
        root=writer._root_object
        if "/Metadata" in root: del root["/Metadata"]
        with open(destination,"wb") as fh: writer.write(fh)
        warnings=["PDF was structurally rewritten. Visible page content is preserved by pypdf, but byte-level signatures and incremental-update history are not preserved."]
        if re.search(rb"/ByteRange\s*\[",source.read_bytes()): warnings.append("The original PDF contained a digital signature. Sanitization invalidates/removes signature validity; DataBreaker does not forge replacement signatures.")
        return warnings
    def validate(self,path):
        try:
            from pypdf import PdfReader
            r=PdfReader(path,strict=True); _=len(r.pages); return True,"PDF reopened by strict parser"
        except Exception as exc:return False,str(exc)
