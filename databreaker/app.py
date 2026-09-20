from __future__ import annotations
import atexit, json, tempfile, uuid, webbrowser
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from .engine import clean_file, scan_file
from .models import CleanMode, NormalizationProfile
from .report import json_report, text_report
from .security import LIMITS, safe_filename

APP_ROOT=Path(__file__).resolve().parent
STATIC=APP_ROOT/"static"
_TEMP_ROOT=tempfile.TemporaryDirectory(prefix="databreaker-")
WORK=Path(_TEMP_ROOT.name)
atexit.register(_TEMP_ROOT.cleanup)
SESSIONS:dict[str,dict]={}
app=FastAPI(title="DataBreaker",docs_url=None,redoc_url=None)
app.mount("/static",StaticFiles(directory=STATIC),name="static")

@app.get("/")
def index():return FileResponse(STATIC/"index.html")

async def _store(upload:UploadFile)->tuple[str,Path]:
    token=uuid.uuid4().hex; directory=WORK/token; directory.mkdir(mode=0o700)
    name=safe_filename(upload.filename or "file"); path=directory/name; total=0
    with open(path,"wb") as fh:
        while chunk:=await upload.read(1024*1024):
            total+=len(chunk)
            if total>LIMITS.max_file_bytes:
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
            SESSIONS[token]={"source":path,"name":upload.filename,"scan":result}
            results.append({"token":token,**result.to_dict()})
        else: results.append(result)
    return {"files":results,"limits":{"max_file_bytes":LIMITS.max_file_bytes}}

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
