from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from databreaker import external
from databreaker.detector import detect


def test_local_exiftool_uses_absolute_all_mode_and_keeps_file_fields(monkeypatch, tmp_path: Path):
    source = tmp_path / "image.png"
    source.write_bytes(b"not-a-real-png")

    captured: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        payload = [{
            "File:System:FileName": "image.png",
            "File:System:FileAccessDate": "2026:09:20 10:50:42+0000",
            "File:FileType": "PNG",
            "File:MIMEType": "image/png",
            "File:ImageWidth": 1254,
            "JUMBF:JUMDType": "(c2pa)-0011-0010-800000aa00389b71",
            "JUMBF:JUMDLabel": "c2pa",
            "CBOR:ActionsSoftwareAgentName": "gpt-image",
            "CBOR:ActionsSoftwareAgentVersion": 2,
            "CBOR:ActionsDigitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
            "CBOR:Claim_Generator_InfoName": "OpenAI Media Service API",
            "PNG:Copy0:Author": "Alice",
            "PNG:Copy1:Author": "Bob",
            "ExifTool:NewUUID": "01234567-89AB-CDEF-0123-456789ABCDEF",
        }]
        return SimpleNamespace(
            stdout=json.dumps(payload).encode(),
            stderr=b"",
            returncode=0,
        )

    monkeypatch.setattr(external.shutil, "which", lambda name: "/usr/bin/exiftool")
    monkeypatch.setattr(external.subprocess, "run", fake_run)

    findings, warnings = external.exiftool_findings(source)
    names = {finding.name for finding in findings}

    assert {
        "FileName",
        "FileAccessDate",
        "FileType",
        "MIMEType",
        "ImageWidth",
        "JUMDType",
        "JUMDLabel",
        "ActionsSoftwareAgentName",
        "ActionsSoftwareAgentVersion",
        "ActionsDigitalSourceType",
        "Claim_Generator_InfoName",
        "Author",
        "NewUUID",
    } <= names

    cmd = captured["cmd"]
    assert "-ee3" in cmd
    assert "RequestAll=3" in cmd
    assert "-G0:4" in cmd
    assert "-u" in cmd
    assert "-a" in cmd
    assert any("full-inventory mode" in warning for warning in warnings)

    fs = next(f for f in findings if f.name == "FileAccessDate")
    assert fs.category == "filesystem/runtime metadata"
    assert "processing environment" in fs.explanation

    generated = next(f for f in findings if f.name == "NewUUID")
    assert generated.category == "generated/runtime metadata"
    assert generated.privacy_impact.value == "low"

    c2pa = next(f for f in findings if f.name == "JUMDType")
    assert c2pa.category == "cryptographic provenance"
    assert c2pa.privacy_impact.value == "medium"

    duplicate_authors = [f for f in findings if f.name == "Author"]
    assert len(duplicate_authors) == 2
    assert {f.value for f in duplicate_authors} == {"Alice", "Bob"}
    assert {f.raw_name for f in duplicate_authors} == {"PNG:Copy0:Author", "PNG:Copy1:Author"}


def test_detector_recognizes_pics_io_baseline_extensions(tmp_path: Path):
    gif = tmp_path / "sample.gif"
    gif.write_bytes(b"GIF89a" + b"\0" * 32)
    assert detect(gif).format == "gif"

    raw = tmp_path / "sample.nef"
    raw.write_bytes(b"II*\x00" + b"\0" * 64)
    assert detect(raw).format == "raw"

    m4v = tmp_path / "sample.m4v"
    m4v.write_bytes(b"\x00\x00\x00\x18ftypM4V " + b"\0" * 24)
    assert detect(m4v).format == "m4v"
