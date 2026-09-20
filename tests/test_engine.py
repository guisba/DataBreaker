from __future__ import annotations

import binascii
import struct
import zlib
import zipfile
from pathlib import Path

import pytest

from databreaker.engine import clean_file, scan_file
from databreaker.models import CleanMode, NormalizationProfile

PNG_SIG=b"\x89PNG\r\n\x1a\n"

def chunk(t: bytes,p: bytes)->bytes:
    return struct.pack(">I",len(p))+t+p+struct.pack(">I",binascii.crc32(t+p)&0xffffffff)

def make_png(path: Path, extra: list[tuple[bytes,bytes]]|None=None):
    ihdr=struct.pack(">IIBBBBB",1,1,8,2,0,0,0)
    raw=b"\x00\xff\x00\x00"
    data=PNG_SIG+chunk(b"IHDR",ihdr)
    for t,p in extra or []: data+=chunk(t,p)
    data+=chunk(b"IDAT",zlib.compress(raw))+chunk(b"IEND",b"")
    path.write_bytes(data)

def make_jpeg(path:Path):
    tiff=(b"II"+struct.pack("<H",42)+struct.pack("<I",8)+struct.pack("<H",1)+
          struct.pack("<HHI",0x0131,2,5)+struct.pack("<I",26)+struct.pack("<I",0)+b"Test\x00")
    app1=b"Exif\x00\x00"+tiff
    seg=b"\xff\xe1"+struct.pack(">H",len(app1)+2)+app1
    sos=b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    path.write_bytes(b"\xff\xd8"+seg+sos+b"\x11\x22\x33\xff\xd9")

def make_docx(path:Path):
    core='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy><dcterms:created>2026-01-01T10:00:00Z</dcterms:created></cp:coreProperties>'''
    with zipfile.ZipFile(path,"w") as z:
        z.writestr("[Content_Types].xml",'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        z.writestr("_rels/.rels",'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
        z.writestr("docProps/core.xml",core)
        z.writestr("word/document.xml",'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>')

def test_png_detect_clean_and_preserve_primary_content(tmp_path:Path):
    p=tmp_path/"image.png"; make_png(p,[(b"tEXt",b"Author\x00Alice"),(b"vpAg",b"private")])
    before=scan_file(p)
    assert any(f.name=="Author" for f in before.findings)
    assert any(f.unknown for f in before.findings)
    result=clean_file(p,tmp_path,CleanMode.EVERYTHING,NormalizationProfile.COMPATIBILITY)
    assert result.sanitized.validation["ok"]
    assert result.original.identity.content_sha256==result.sanitized.identity.content_sha256
    assert not any(f.name=="Author" for f in result.sanitized.findings)

def test_png_ai_workflow_detection(tmp_path:Path):
    p=tmp_path/"ai.png"
    params=b"parameters\x00a cat\nSteps: 20, Sampler: Euler a, Seed: 1234, Model: demo"
    make_png(p,[(b"tEXt",params)])
    scan=scan_file(p)
    names={f.name for f in scan.findings}
    assert "Stable Diffusion-style generation parameters" in names
    assert "Seed" in names and "Sampler" in names

def test_jpeg_exif_removed_without_changing_scan_data(tmp_path:Path):
    p=tmp_path/"photo.jpg"; make_jpeg(p)
    before=scan_file(p)
    assert any(f.name=="Software" for f in before.findings)
    result=clean_file(p,tmp_path,CleanMode.SAFE,NormalizationProfile.COMPATIBILITY)
    assert result.validation_ok
    assert before.identity.content_sha256==result.sanitized.identity.content_sha256
    assert not any(f.name=="Software" for f in result.sanitized.findings)

def test_zip_metadata_cleaning_preserves_member_bytes(tmp_path:Path):
    p=tmp_path/"bundle.zip"
    with zipfile.ZipFile(p,"w") as z:
        info=zipfile.ZipInfo("folder/private.txt",(2025,5,4,3,2,0)); info.extra=b"\x0a\x00\x00\x00"; z.writestr(info,b"secret payload"); z.comment=b"created by Alice"
    result=clean_file(p,tmp_path,CleanMode.DEEP,NormalizationProfile.MINIMAL)
    assert result.original.identity.content_sha256==result.sanitized.identity.content_sha256
    with zipfile.ZipFile(result.output_path) as z:
        assert z.read("folder/private.txt")==b"secret payload"
        assert not z.comment
        assert not z.getinfo("folder/private.txt").extra

def test_ooxml_properties_cleaned_without_document_text_change(tmp_path:Path):
    p=tmp_path/"report.docx"; make_docx(p)
    before=scan_file(p)
    assert any(f.name=="creator" and "Alice" in str(f.value) for f in before.findings)
    result=clean_file(p,tmp_path,CleanMode.DEEP,NormalizationProfile.COMPATIBILITY)
    assert result.original.identity.content_sha256==result.sanitized.identity.content_sha256
    with zipfile.ZipFile(result.output_path) as z:
        assert b"Hello" in z.read("word/document.xml")
        assert b"Alice" not in z.read("docProps/core.xml")

def test_malformed_png_rejected(tmp_path:Path):
    p=tmp_path/"bad.png"; p.write_bytes(PNG_SIG+b"\x00\x00\x00\x10IHDRoops")
    with pytest.raises(ValueError): scan_file(p)

def test_custom_normalization_controls_archive_timestamps(tmp_path:Path):
    source=tmp_path/"custom.zip"
    with zipfile.ZipFile(source,"w") as z:
        z.writestr(zipfile.ZipInfo("note.txt",(2025,6,7,8,10,0)),b"payload")
    normalized=clean_file(
        source,tmp_path,CleanMode.DEEP,NormalizationProfile.CUSTOM,
        options={"preserve_color_profile":True,"preserve_archive_timestamps":False},
    )
    with zipfile.ZipFile(normalized.output_path) as z:
        assert z.getinfo("note.txt").date_time==(2000,1,1,0,0,0)
    assert normalized.synthetic_fields

    source2=tmp_path/"preserve.zip"
    with zipfile.ZipFile(source2,"w") as z:
        z.writestr(zipfile.ZipInfo("note.txt",(2025,6,7,8,10,0)),b"payload")
    preserved=clean_file(
        source2,tmp_path,CleanMode.DEEP,NormalizationProfile.CUSTOM,
        options={"preserve_color_profile":True,"preserve_archive_timestamps":True},
    )
    with zipfile.ZipFile(preserved.output_path) as z:
        assert z.getinfo("note.txt").date_time==(2025,6,7,8,10,0)


def test_analysis_only_formats_do_not_advertise_cleaning(tmp_path:Path):
    seven=tmp_path/'sample.7z'; seven.write_bytes(b"7z\xbc\xaf\x27\x1c"+b"\0"*32)
    assert scan_file(seven).capabilities['clean'] is False

    tar_path=tmp_path/'sample.tar'
    import tarfile, io
    with tarfile.open(tar_path,'w') as tf:
        info=tarfile.TarInfo('note.txt'); data=b'hello'; info.size=len(data); tf.addfile(info,io.BytesIO(data))
    assert scan_file(tar_path).capabilities['clean'] is False

    heif=tmp_path/'sample.heic'; heif.write_bytes(b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1")
    assert scan_file(heif).capabilities['clean'] is False
