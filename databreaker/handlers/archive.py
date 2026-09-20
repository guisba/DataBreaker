from __future__ import annotations
import hashlib, io, tarfile, zipfile
from pathlib import Path
from .base import FormatHandler
from ..models import CleanMode, Confidence, Finding, NormalizationProfile, PrivacyImpact
from ..security import LIMITS, is_safe_archive_member

class ArchiveHandler(FormatHandler):
    formats=("zip","tar","7z")
    def scan(self,path):
        findings=[];warnings=[]; content=hashlib.sha256()
        with open(path,"rb") as fh: header=fh.read(6)
        if path.suffix.lower()==".7z" or header==b"7z\xbc\xaf\x27\x1c":
            return [Finding("7z container","7z","present","archive","structural metadata",PrivacyImpact.STRUCTURAL,Confidence.CONFIRMED,"7z detected. Full inspection requires an optional external/library parser.",False,"unsupported")],["7z deep inspection/cleaning is not available in the minimal dependency set."],hashlib.sha256(path.read_bytes()).hexdigest()
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                infos=z.infolist()
                if len(infos)>LIMITS.max_archive_entries: raise ValueError("Archive entry limit exceeded")
                total=sum(i.file_size for i in infos)
                if total>LIMITS.max_archive_uncompressed_bytes: raise ValueError("Archive uncompressed size limit exceeded")
                if z.comment: findings.append(Finding("Archive comment","ZIP comment",z.comment.decode("utf-8","replace")[:16384],"ZIP EOCD","archive metadata",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"Archive-level comment.",True))
                for i in infos:
                    if not is_safe_archive_member(i.filename): warnings.append(f"Unsafe archive path: {i.filename}")
                    ratio=i.file_size/max(1,i.compress_size)
                    if ratio>LIMITS.max_archive_ratio: warnings.append(f"High compression ratio ({ratio:.0f}x): {i.filename}")
                    findings.append(Finding("Member filename","filename",i.filename,"ZIP central directory","filesystem/path information",PrivacyImpact.HIGH if "/" in i.filename else PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"Archive member names can expose project names, usernames, or paths.",False,"renaming changes archive semantics"))
                    findings.append(Finding("Member timestamp","timestamp",str(i.date_time),i.filename,"timestamps",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"ZIP member modification time.",True))
                    if i.extra: findings.append(Finding("ZIP extra fields","extra",i.extra.hex()[:2048],i.filename,"archive metadata",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"ZIP extra fields may contain extended timestamps, NTFS data, Unix IDs, or application-specific values.",True))
                    if i.external_attr: findings.append(Finding("External attributes","external_attr",hex(i.external_attr),i.filename,"archive metadata",PrivacyImpact.LOW,Confidence.CONFIRMED,"May reveal host filesystem permissions or OS conventions.",True))
                    if not i.is_dir() and i.file_size<=8*1024*1024:
                        try: content.update(i.filename.encode()+b"\0"+hashlib.sha256(z.read(i)).digest())
                        except Exception: pass
            return findings,warnings,content.hexdigest()
        try:
            with tarfile.open(path,"r:*") as t:
                members=t.getmembers()
                if len(members)>LIMITS.max_archive_entries: raise ValueError("Archive entry limit exceeded")
                for m in members:
                    findings.extend([
                        Finding("Member filename","name",m.name,"TAR header","filesystem/path information",PrivacyImpact.HIGH if "/" in m.name else PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"Archive path/name.",False),
                        Finding("UID/GID","uid/gid",f"{m.uid}/{m.gid}",m.name,"filesystem identity",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Unix user/group numeric identifiers stored in the TAR header.",True),
                        Finding("User/group name","uname/gname",f"{m.uname}/{m.gname}",m.name,"filesystem identity",PrivacyImpact.HIGH,Confidence.CONFIRMED,"Unix account/group names may identify a workstation user.",True),
                        Finding("Timestamp","mtime",m.mtime,m.name,"timestamps",PrivacyImpact.MEDIUM,Confidence.CONFIRMED,"TAR modification timestamp.",True),
                    ])
            return findings,warnings,hashlib.sha256(path.read_bytes()).hexdigest()
        except tarfile.TarError as exc:return [],[f"Archive parser warning: {exc}"],hashlib.sha256(path.read_bytes()).hexdigest()
    def clean(self,source,destination,mode,profile,options=None):
        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as zin, zipfile.ZipFile(destination,"w") as zout:
                for i in zin.infolist():
                    if not is_safe_archive_member(i.filename): raise ValueError("Unsafe archive path")
                    data=zin.read(i)
                    ni=zipfile.ZipInfo(i.filename, date_time=i.date_time if (mode==CleanMode.SAFE or profile==NormalizationProfile.COMPATIBILITY or (profile==NormalizationProfile.CUSTOM and bool((options or {}).get("preserve_archive_timestamps",False)))) else ((2000,1,1,0,0,0) if profile in (NormalizationProfile.GENERIC,NormalizationProfile.CUSTOM) else (1980,1,1,0,0,0)))
                    ni.compress_type=i.compress_type
                    ni.external_attr=0 if mode==CleanMode.EVERYTHING else i.external_attr
                    ni.comment=b""
                    ni.extra=b"" if mode in (CleanMode.DEEP,CleanMode.EVERYTHING) else i.extra
                    zout.writestr(ni,data)
            return ["ZIP entries were reconstructed without modifying member payload bytes; archive-level ordering/compression metadata may differ."]
        raise ValueError("Automatic cleaning is currently supported for ZIP archives only")
    def validate(self,path):
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as z: bad=z.testzip(); return (bad is None,"ZIP CRC validation passed" if bad is None else f"Bad member CRC: {bad}")
            except Exception as exc:return False,str(exc)
        try:
            with tarfile.open(path,"r:*") as t:t.getmembers();return True,"TAR parsed"
        except Exception as exc:return False,str(exc)
