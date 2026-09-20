const PYODIDE_VERSION='314.0.7';
const PYODIDE_BASE=`https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
const MODULES=[
  '__init__.py','detector.py','engine.py','explanations.py','external.py','fingerprint.py','models.py','report.py','security.py','tiff.py','xmp.py',
  'handlers/__init__.py','handlers/archive.py','handlers/audio.py','handlers/base.py','handlers/generic.py','handlers/iso_bmff.py','handlers/jpeg.py','handlers/ooxml.py','handlers/pdf.py','handlers/png.py','handlers/svg.py','handlers/webp.py'
];
let pyodide=null;
function safeName(name){return String(name||'file').replace(/[\\/:*?"<>|\x00-\x1f]/g,'_').replace(/^\.+/,'file').slice(0,180)||'file'}
async function loadSourceTree(){
  pyodide.FS.mkdirTree('/app/databreaker/handlers');
  for(const rel of MODULES){
    const response=await fetch(`./python/databreaker/${rel}`,{cache:'no-cache'});
    if(!response.ok)throw new Error(`Could not load Python module ${rel}`);
    pyodide.FS.writeFile(`/app/databreaker/${rel}`,await response.text(),{encoding:'utf8'});
  }
  await pyodide.runPythonAsync("import sys; sys.path.insert(0, '/app')");
}
async function init(){
  importScripts(`${PYODIDE_BASE}pyodide.js`);
  pyodide=await loadPyodide({indexURL:PYODIDE_BASE});
  await pyodide.loadPackage('micropip');
  await pyodide.runPythonAsync("import micropip; await micropip.install(['pypdf>=5,<7','mutagen>=1.47,<2'])");
  await loadSourceTree();
  await pyodide.runPythonAsync('from databreaker.engine import scan_file, clean_file; from databreaker.models import CleanMode, NormalizationProfile; from databreaker.report import json_report, text_report');
}
function writeInput(name,buffer,id){
  const dir=`/work/${id}`;pyodide.FS.mkdirTree(dir);const path=`${dir}/${safeName(name)}`;pyodide.FS.writeFile(path,new Uint8Array(buffer));return {dir,path};
}
async function pyString(code,vars={}){for(const [k,v] of Object.entries(vars))pyodide.globals.set(k,v);return await pyodide.runPythonAsync(code)}
async function scan(msg){
  const {dir,path}=writeInput(msg.name,msg.bytes,msg.id);
  try{
    const json=await pyString("import json; from pathlib import Path; json.dumps(scan_file(Path(db_path), db_name).to_dict(), ensure_ascii=False)",{db_path:path,db_name:msg.name});
    return JSON.parse(json);
  }finally{await pyString("import shutil; shutil.rmtree(db_dir, ignore_errors=True)",{db_dir:dir})}
}
async function clean(msg){
  const {dir,path}=writeInput(msg.name,msg.bytes,msg.id);
  try{
    const options=JSON.stringify(msg.options||{});
    const payload=await pyString(`
import json
from pathlib import Path
_result=clean_file(Path(db_path),Path(db_dir),CleanMode(db_mode),NormalizationProfile(db_profile),db_name,json.loads(db_options))
json.dumps({"result":_result.to_dict(),"output_path":_result.output_path,"report_json":json_report(_result),"report_text":text_report(_result)},ensure_ascii=False)
`,{db_path:path,db_dir:dir,db_name:msg.name,db_mode:msg.mode,db_profile:msg.profile,db_options:options});
    const parsed=JSON.parse(payload),fileBytes=pyodide.FS.readFile(parsed.output_path);
    return {result:parsed.result,fileBytes:fileBytes.buffer,fileName:parsed.output_path.split('/').pop(),reportJson:parsed.report_json,reportText:parsed.report_text};
  }finally{await pyString("import shutil; shutil.rmtree(db_dir, ignore_errors=True)",{db_dir:dir})}
}
(async()=>{try{await init();postMessage({type:'ready'})}catch(error){postMessage({type:'fatal',error:String(error?.stack||error)})}})();
onmessage=async event=>{
  const msg=event.data||{};if(!msg.id)return;
  try{
    const result=msg.action==='scan'?await scan(msg):msg.action==='clean'?await clean(msg):(()=>{throw new Error('Unknown browser-engine action')})();
    const transfer=result?.fileBytes instanceof ArrayBuffer?[result.fileBytes]:[];postMessage({id:msg.id,ok:true,result},transfer);
  }catch(error){postMessage({id:msg.id,ok:false,error:String(error?.stack||error)})}
};
