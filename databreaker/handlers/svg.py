from __future__ import annotations
import hashlib, re, xml.etree.ElementTree as ET
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..explanations import explain, privacy_for

class SVGHandler(FormatHandler):
    formats=("svg",)
    def scan(self,path):
        raw=path.read_bytes(); findings=[]; warnings=[]
        try: root=ET.fromstring(raw)
        except ET.ParseError as exc:return [],[f"Malformed SVG XML: {exc}"],hashlib.sha256(raw).hexdigest()
        for elem in root.iter():
            local=elem.tag.rsplit("}",1)[-1].lower()
            if local in {"metadata","title","desc"} and (elem.text or list(elem)):
                text="".join(elem.itertext()).strip()[:16384]
                findings.append(Finding(local,elem.tag,text or "<structured XML>","SVG XML","SVG metadata",privacy_for(local,text),Confidence.CONFIRMED,explain(local),True))
            for k,v in elem.attrib.items():
                if any(x in k.lower() for x in ("sodipodi","inkscape","adobe","creator","author","version")):
                    findings.append(Finding(k,k,v,"SVG attribute","editor metadata",privacy_for(k,v),Confidence.HIGH,explain(k),True))
        for ns in set(re.findall(rb'xmlns(?::\w+)?=["\']([^"\']+)',raw)):
            s=ns.decode("utf-8","replace")
            if not any(k in s for k in ("w3.org","svg")):
                findings.append(Finding("XML namespace","xmlns",s,"SVG root","unknown/unclassified",PrivacyImpact.UNKNOWN,Confidence.UNKNOWN,"Additional namespace can identify an editor or extension.",True,unknown=True))
        return findings,warnings,hashlib.sha256(ET.tostring(root,encoding="utf-8")).hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        raw=source.read_bytes(); root=ET.fromstring(raw)
        for parent in root.iter():
            for child in list(parent):
                if child.tag.rsplit("}",1)[-1].lower()=="metadata": parent.remove(child)
        if mode in (CleanMode.DEEP,CleanMode.EVERYTHING):
            for elem in root.iter():
                for k in list(elem.attrib):
                    if any(x in k.lower() for x in ("sodipodi","inkscape","adobe","creator","author")): del elem.attrib[k]
        destination.write_bytes(ET.tostring(root,encoding="utf-8",xml_declaration=True)); return ["SVG was XML-reserialized; visible vector geometry is intended to remain unchanged."]
    def validate(self,path):
        try: root=ET.fromstring(path.read_bytes()); return (root.tag.rsplit("}",1)[-1].lower()=="svg","SVG XML parsed")
        except Exception as exc:return False,str(exc)
