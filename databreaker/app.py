from __future__ import annotations
import atexit, json, os, shutil, tempfile, uuid, webbrowser
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from .engine import clean_file, scan_file
from .models import CleanMode, NormalizationProfile
from .report import json_report, text_report
from .security import LIMITS, safe_filename

APP_ROOT=Path(__file__).resolve().parent
STATIC=APP_ROOT/"static"
_TEMP_ROOT=tempfile.TemporaryDirectory(prefix="databreaker-")
WORK=Path(_TEMP_ROOT.name)
HOSTED_MAX_FILE_BYTES=4*1024*1024
atexit.register(_TEMP_ROOT.cleanup)
SESSIONS:dict[str,dict]={}
STATELESS=bool(os.environ.get("VERCEL") or os.environ.get("DATABREAKER_STATELESS"))
app=FastAPI(title="DataBreaker",docs_url=None,redoc_url=None)
app.mount("/static",StaticFiles(directory=STATIC),name="static")

@app.get("/")
def index():return FileResponse(STATIC/"index.html")

async def _store(upload:UploadFile)->tuple[str,Path]:
    token=uuid.uuid4().hex; directory=WORK/token; directory.mkdir(mode=0o700)
    name=safe_filename(upload.filename or "file"); path=directory/name; total=0
    max_bytes=HOSTED_MAX_FILE_BYTES if STATELESS else LIMITS.max_file_bytes
    with open(path,"wb") as fh:
        while chunk:=await upload.read(1024*1024):
            total+=len(chunk)
            if total>max_bytes:
                fh.close(); path.unlink(missing_ok=True); raise HTTPException(413,"File exceeds local safety limit")
            fh.write(chunk)
    return token,path

@app.post("/api/scan")
async def scan(files:list[UploadFile]=File(...)):
    if len(files)>LIMITS.max_files: raise HTTPException(400,"Too many files")
    results=[]
    for upload in files:
        token,path=await _store(upload)
        try: result=scan_file(path,upload.filename)
        except Exception as exc: result={"error":str(exc),"identity":{"filename":upload.filename}}
        if hasattr(result,"to_dict"):
            if STATELESS:
                payload={"token":token,**result.to_dict()}
                shutil.rmtree(path.parent,ignore_errors=True)
            else:
                SESSIONS[token]={"source":path,"name":upload.filename,"scan":result}
                payload={"token":token,**result.to_dict()}
            results.append(payload)
        else:
            shutil.rmtree(path.parent,ignore_errors=True)
            results.append(result)
    return {"files":results,"limits":{"max_file_bytes":HOSTED_MAX_FILE_BYTES if STATELESS else LIMITS.max_file_bytes}}


@app.get("/api/runtime")
def runtime():
    return {"hosted":STATELESS,"temporary_processing":True,"telemetry":False,"max_file_bytes":HOSTED_MAX_FILE_BYTES if STATELESS else LIMITS.max_file_bytes}

@app.post("/api/clean-direct")
async def clean_direct(
    file:UploadFile=File(...),
    mode:CleanMode=Form(CleanMode.SAFE),
    profile:NormalizationProfile=Form(NormalizationProfile.COMPATIBILITY),
    preserve_color_profile:bool=Form(True),
    preserve_archive_timestamps:bool=Form(False),
):
    token,path=await _store(file)
    try:
        result=clean_file(path,path.parent,mode,profile,file.filename,{
            "preserve_color_profile":preserve_color_profile,
            "preserve_archive_timestamps":preserve_archive_timestamps,
        })
    except Exception as exc:
        shutil.rmtree(path.parent,ignore_errors=True)
        raise HTTPException(400,str(exc)) from exc

    output=Path(result.output_path)
    payload=json.dumps(result.to_dict(),ensure_ascii=False).encode("utf-8")
    report_json=json_report(result).encode("utf-8")
    report_text=text_report(result).encode("utf-8")
    boundary=f"databreaker-{uuid.uuid4().hex}"
    clean_name=safe_filename(output.name)

    def part_header(name:str,content_type:str,filename:str|None=None)->bytes:
        disp=f'form-data; name="{name}"'
        if filename: disp+=f'; filename="{safe_filename(filename)}"'
        return (f"--{boundary}\r\nContent-Disposition: {disp}\r\nContent-Type: {content_type}\r\n\r\n").encode("utf-8")

    def stream():
        try:
            yield part_header("result","application/json")
            yield payload; yield b"\r\n"
            yield part_header("report_json","application/json","databreaker-report.json")
            yield report_json; yield b"\r\n"
            yield part_header("report_text","text/plain; charset=utf-8","databreaker-report.txt")
            yield report_text; yield b"\r\n"
            yield part_header("file","application/octet-stream",clean_name)
            with open(output,"rb") as fh:
                while chunk:=fh.read(1024*1024): yield chunk
            yield b"\r\n"
            yield f"--{boundary}--\r\n".encode("utf-8")
        finally:
            shutil.rmtree(path.parent,ignore_errors=True)

    return StreamingResponse(stream(),media_type=f"multipart/form-data; boundary={boundary}",headers={"Cache-Control":"no-store"})

@app.post("/api/clean/{token}")
def clean(token:str,mode:CleanMode=Form(CleanMode.SAFE),profile:NormalizationProfile=Form(NormalizationProfile.COMPATIBILITY),preserve_color_profile:bool=Form(True),preserve_archive_timestamps:bool=Form(False)):
    session=SESSIONS.get(token)
    if not session: raise HTTPException(404,"Unknown or expired file token")
    try:
        result=clean_file(session["source"],session["source"].parent,mode,profile,session["name"],{"preserve_color_profile":preserve_color_profile,"preserve_archive_timestamps":preserve_archive_timestamps})
    except Exception as exc: raise HTTPException(400,str(exc)) from exc
    session["clean"]=result
    return result.to_dict()

@app.get("/api/download/{token}")
def download(token:str):
    s=SESSIONS.get(token); result=s.get("clean") if s else None
    if not result: raise HTTPException(404,"No sanitized file")
    path=Path(result.output_path); return FileResponse(path,filename=path.name,media_type="application/octet-stream")

@app.get("/api/report/{token}.{kind}")
def report(token:str,kind:str):
    s=SESSIONS.get(token)
    if not s: raise HTTPException(404,"Unknown token")
    obj=s.get("clean") or s.get("scan")
    if kind=="json": return JSONResponse(json.loads(json_report(obj)),headers={"Content-Disposition":f'attachment; filename="databreaker-report-{token[:8]}.json"'})
    if kind=="txt": return PlainTextResponse(text_report(obj),headers={"Content-Disposition":f'attachment; filename="databreaker-report-{token[:8]}.txt"'})
    raise HTTPException(404,"Unknown report format")
