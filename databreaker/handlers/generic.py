from __future__ import annotations
import hashlib
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Finding, NormalizationProfile

class UnknownHandler(FormatHandler):
    formats=("unknown","7z","matroska")
    def scan(self,path):return [],["Format is recognized only partially or unsupported for deep metadata parsing."],hashlib.sha256(path.read_bytes()).hexdigest()
    def clean(self,source,destination,mode,profile,options=None):raise ValueError("Cleaning is not supported for this format")
    def validate(self,path):return (path.is_file() and path.stat().st_size>0,"Basic file presence validation only")
    def supports_cleaning(self):return False
