from __future__ import annotations
import binascii, struct, zlib
from fastapi.testclient import TestClient
from databreaker.app import app

PNG_SIG=b"\x89PNG\r\n\x1a\n"
def chunk(t,p): return struct.pack(">I",len(p))+t+p+struct.pack(">I",binascii.crc32(t+p)&0xffffffff)
def sample_png():
    ihdr=struct.pack(">IIBBBBB",1,1,8,2,0,0,0)
    return PNG_SIG+chunk(b"IHDR",ihdr)+chunk(b"tEXt",b"Author\x00Alice")+chunk(b"IDAT",zlib.compress(b"\x00\xff\x00\x00"))+chunk(b"IEND",b"")

def test_scan_clean_download_report_roundtrip():
    client=TestClient(app)
    response=client.post('/api/scan',files=[('files',('sample.png',sample_png(),'image/png'))])
    assert response.status_code==200
    item=response.json()['files'][0]
    assert item['identity']['format']=='png'
    assert any(f['name']=='Author' for f in item['findings'])
    token=item['token']
    cleaned=client.post(f'/api/clean/{token}',data={'mode':'safe','profile':'compatibility'})
    assert cleaned.status_code==200
    assert cleaned.json()['sanitized']['validation']['ok']
    assert client.get(f'/api/download/{token}').status_code==200
    report=client.get(f'/api/report/{token}.json')
    assert report.status_code==200 and report.json()['tool']=='DataBreaker'
