const PYODIDE_VERSION='314.0.7';
const PYODIDE_CDN_BASE=`https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
const PYODIDE_BASE=PYODIDE_CDN_BASE;
const MODULES=[
  '__init__.py','detector.py','engine.py','explanations.py','external.py','fingerprint.py','models.py','report.py','security.py','tiff.py','xmp.py',
  'handlers/__init__.py','handlers/archive.py','handlers/audio.py','handlers/base.py','handlers/generic.py','handlers/iso_bmff.py','handlers/jpeg.py','handlers/ooxml.py','handlers/pdf.py','handlers/png.py','handlers/svg.py','handlers/webp.py'
];

let pyodide=null;
let exiftoolRuntimePromise=null;
const optionalPackages={pypdf:false,mutagen:false};
let micropipReady=false;

const FS_FIELDS=new Set([
  'SourceFile','FileName','Directory','FileSize','FileModifyDate','FileAccessDate',
  'FileInodeChangeDate','FilePermissions','FileCreateDate'
]);
const STRUCTURAL_FIELDS=new Set([
  'FileType','FileTypeExtension','MIMEType','ImageWidth','ImageHeight','BitDepth',
  'ColorType','Compression','Filter','Interlace','ImageSize','Megapixels',
  'PDFVersion','PageCount','Linearized','PageMode','Duration','VideoFrameRate',
  'AudioSampleRate','AudioChannels'
]);
const IMPACT_RANK={unknown:0,low:1,structural:1,medium:2,high:3,critical:4};

function safeName(name){
  return String(name||'file').replace(/[\\/:*?"<>|\x00-\x1f]/g,'_').replace(/^\.+/,'file').slice(0,180)||'file';
}

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
  const {loadPyodide}=await import(`${PYODIDE_BASE}pyodide.mjs`);
  pyodide=await loadPyodide({indexURL:PYODIDE_BASE,packageBaseUrl:PYODIDE_CDN_BASE});
  await loadSourceTree();
  await pyodide.runPythonAsync(
    'from databreaker.engine import scan_file, clean_file; from databreaker.models import CleanMode, NormalizationProfile'
  );
}

function optionalPackageFor(name){
  const lower=String(name||'').toLowerCase();
  if(lower.endsWith('.pdf'))return 'pypdf';
  if(/\.(mp3|flac|ogg|wav|mp4|mov|m4a|m4b)$/i.test(lower))return 'mutagen';
  return null;
}

async function ensureOptionalPackage(name){
  const pkg=optionalPackageFor(name);
  if(!pkg||optionalPackages[pkg])return;
  if(!micropipReady){await pyodide.loadPackage('micropip');micropipReady=true}
  const spec=pkg==='pypdf'?'pypdf>=5,<7':'mutagen>=1.47,<2';
  pyodide.globals.set('db_optional_spec',spec);
  try{await pyodide.runPythonAsync("import micropip; await micropip.install(db_optional_spec)")}
  finally{pyodide.globals.delete('db_optional_spec')}
  optionalPackages[pkg]=true;
}

function writeInput(name,buffer,id){
  const dir=`/work/${id}`;
  pyodide.FS.mkdirTree(dir);
  const path=`${dir}/${safeName(name)}`;
  pyodide.FS.writeFile(path,new Uint8Array(buffer));
  return {dir,path};
}

async function pyString(code,vars={}){
  for(const [k,v] of Object.entries(vars))pyodide.globals.set(k,v);
  return await pyodide.runPythonAsync(code);
}

async function getExifToolRuntime(){
  // ZeroPerl 1.0.11 identifies browsers through window+document. Web Workers
  // intentionally expose neither, so provide minimal detection aliases before
  // evaluating the module. The library only uses these names for environment
  // detection; all I/O still goes through fetch() and the in-memory WASI FS.
  if(typeof globalThis.window==='undefined')globalThis.window=globalThis;
  if(typeof globalThis.document==='undefined')globalThis.document=Object.freeze({});
  if(!exiftoolRuntimePromise)exiftoolRuntimePromise=import('./exiftool-runtime.js');
  return await exiftoolRuntimePromise;
}

function valueText(value){
  if(value===null)return 'null';
  if(typeof value==='string')return value.length>16384?value.slice(0,16384)+'…':value;
  if(typeof value==='number'||typeof value==='boolean')return value;
  try{
    const text=JSON.stringify(value);
    return text.length>16384?text.slice(0,16384)+'…':value;
  }catch{return String(value)}
}

function splitExifName(rawName){
  const parts=String(rawName).split(':');
  const short=parts.pop()||String(rawName);
  return {short,group:parts.join(':')||'ExifTool'};
}

function exifCategory(rawName,short,group){
  const all=`${rawName} ${short} ${group}`.toLowerCase();
  if(FS_FIELDS.has(short))return 'filesystem/runtime metadata';
  if(STRUCTURAL_FIELDS.has(short))return 'file/structural metadata';
  if(/c2pa|jumbf|jumd|cbor|contentauth|claim.generator|assertion/.test(all))return 'cryptographic provenance';
  if(/gps|location|latitude|longitude|altitude/.test(all))return 'location metadata';
  if(/maker|canon|nikon|sony|apple|samsung|google|motorola|fuji|dji|gopro|olympus|pentax|panasonic/.test(all))return 'manufacturer/application metadata';
  if(/xmp|iptc|exif/.test(all))return 'embedded metadata';
  return 'extended metadata';
}

function exifImpact(rawName,short,group){
  const all=`${rawName} ${short} ${group}`.toLowerCase();
  if(/gps|latitude|longitude|location/.test(all))return 'critical';
  if(/serial|owner|email|username|account|instanceid|documentid|originaldocumentid|uuid/.test(all))return 'high';
  if(/c2pa|jumbf|jumd|cbor|claim.generator|assertion|digital.source/.test(all))return 'medium';
  if(/author|creator|artist|copyright|software|producer|make|model|lens/.test(all))return 'medium';
  if(STRUCTURAL_FIELDS.has(short))return 'structural';
  if(/unknown|0x[0-9a-f]+/i.test(short))return 'unknown';
  return 'low';
}

function exifExplanation(rawName,short,group){
  if(FS_FIELDS.has(short)){
    return 'Filesystem/runtime attribute reported by ExifTool. In browser or hosted execution this describes the sandbox copy and is not necessarily embedded in the original file.';
  }
  const all=`${rawName} ${group}`.toLowerCase();
  if(/c2pa|jumbf|jumd|cbor/.test(all)){
    return 'Field decoded from C2PA/JUMBF/CBOR provenance by ExifTool. It is shown verbatim as evidence; signature validity is not inferred from presence alone.';
  }
  if(/unknown|0x[0-9a-f]+/i.test(short)){
    return 'ExifTool exposed an unknown or proprietary field. DataBreaker preserves it in the inventory instead of hiding it.';
  }
  return 'Field reported by ExifTool in full-inventory mode (-ee3, RequestAll=3, duplicates and unknown tags enabled).';
}

function exiftoolFindings(row){
  const findings=[];
  for(const [rawName,rawValue] of Object.entries(row||{})){
    const {short,group}=splitExifName(rawName);
    const unknown=/unknown|0x[0-9a-f]+/i.test(short);
    const provenance=/c2pa|jumbf|jumd|cbor|claim.generator|assertion/i.test(`${rawName} ${group}`);
    findings.push({
      name:short,
      raw_name:rawName,
      value:valueText(rawValue),
      source:`ExifTool-WASM/${group}`,
      category:exifCategory(rawName,short,group),
      privacy_impact:exifImpact(rawName,short,group),
      confidence:unknown?'unknown':'confirmed',
      explanation:exifExplanation(rawName,short,group),
      removable:false,
      removal_risk:'full-inventory field; removal is claimed only when a native cleaner verifies it',
      cryptographically_signed:provenance&&/signature|ocsp|tst/i.test(short),
      evidence:[`ExifTool tag=${rawName}`],
      unknown,
      signature_status:provenance?'present_unverified':'not_applicable'
    });
  }
  return findings;
}

function mergeInventory(scan,row,version){
  const semantic=Array.isArray(scan.findings)?scan.findings:[];
  const byName=new Map();
  for(const f of semantic){
    const key=String(f.name||'').toLowerCase();
    if(!byName.has(key))byName.set(key,[]);
    byName.get(key).push(f);
  }

  const inventory=exiftoolFindings(row);
  const represented=new Set();
  for(const f of inventory){
    const key=String(f.name||'').toLowerCase();
    const candidates=byName.get(key)||[];
    if(candidates.length){
      represented.add(key);
      for(const s of candidates){
        if((IMPACT_RANK[s.privacy_impact]||0)>(IMPACT_RANK[f.privacy_impact]||0))f.privacy_impact=s.privacy_impact;
        if(s.removable){f.removable=true;f.removal_risk=s.removal_risk||f.removal_risk}
        if(s.explanation&&s.explanation!==f.explanation)f.explanation+=` ${s.explanation}`;
        if(s.cryptographically_signed)f.cryptographically_signed=true;
        if(Array.isArray(s.evidence))f.evidence=[...new Set([...(f.evidence||[]),...s.evidence])];
      }
    }
  }

  const leftovers=semantic.filter(f=>{
    const key=String(f.name||'').toLowerCase();
    return !represented.has(key)||String(f.raw_name||'').startsWith('derived.')||
      /workflow|stable diffusion|comfyui|c2pa\/jumbf provenance/i.test(String(f.name||''));
  });
  scan.findings=[...inventory,...leftovers];
  scan.inventory={
    engine:'ExifTool-WASM',
    version,
    mode:'all',
    args:['-json','-m','-q','-q','-a','-u','-G0:4','-s','-ee3','-api','RequestAll=3','-api','LargeFileSupport=1'],
    fields:inventory.length
  };
  return scan;
}

async function enrichScan(name,bytes,scan){
  try{
    const runtime=await getExifToolRuntime();
    const row=await runtime.extractAllMetadata(name,bytes instanceof Uint8Array?bytes:new Uint8Array(bytes));
    return mergeInventory(scan,row,runtime.EXIFTOOL_VERSION||'unknown');
  }catch(error){
    scan.warnings=scan.warnings||[];
    scan.warnings.push(`Full ExifTool-WASM inventory unavailable: ${error?.message||error}`);
    scan.inventory={engine:'ExifTool-WASM',mode:'all',available:false};
    return scan;
  }
}

function stableValue(value){
  return typeof value==='string'?value:JSON.stringify(value);
}

function findingKey(f){
  return `${f.raw_name}\u0000${f.source}\u0000${stableValue(f.value)}`;
}

function identityKey(f){
  return `${f.raw_name}\u0000${f.source}`;
}

function buildFullDiff(before,after){
  const b=new Map((before.findings||[]).map(f=>[findingKey(f),f]));
  const a=new Map((after.findings||[]).map(f=>[findingKey(f),f]));
  const removed=[...b].filter(([k])=>!a.has(k)).map(([,f])=>f);
  const retained=[...b].filter(([k])=>a.has(k)).map(([,f])=>f);
  const beforeIdentity=new Map((before.findings||[]).map(f=>[identityKey(f),f]));
  const afterIdentity=new Map((after.findings||[]).map(f=>[identityKey(f),f]));
  const normalized=[];
  for(const [key,old] of beforeIdentity){
    const next=afterIdentity.get(key);
    if(next&&stableValue(old.value)!==stableValue(next.value)){
      normalized.push({
        name:old.name,raw_name:old.raw_name,source:old.source,
        before:old.value,after:next.value,synthetic:false
      });
    }
  }
  const remaining_sensitive=(after.findings||[]).filter(f=>['critical','high'].includes(f.privacy_impact));
  const warnings=remaining_sensitive.length?['Potentially identifying information remains after cleaning.']:[];
  return {removed,retained,normalized,remaining_sensitive,warnings};
}

function fullJsonReport(result){
  return JSON.stringify({...result,report_version:'2.0',tool:'DataBreaker'},null,2);
}

function fullTextReport(result){
  const lines=[
    'DataBreaker — Original → Sanitized',
    `Mode: ${result.mode}`,
    `Profile: ${result.profile}`,
    `Validation: ${result.validation_ok?'PASS':'WARNING'}`,
    `Original inventory fields: ${result.original?.findings?.length||0}`,
    `Sanitized inventory fields: ${result.sanitized?.findings?.length||0}`,
    `Removed: ${result.diff?.removed?.length||0}`,
    `Retained: ${result.diff?.retained?.length||0}`,
    `Normalized: ${result.diff?.normalized?.length||0}`,
    `Sensitive remaining: ${result.diff?.remaining_sensitive?.length||0}`
  ];
  for(const f of result.sanitized?.findings||[]){
    lines.push(`[${f.privacy_impact}] ${f.raw_name}: ${stableValue(f.value)} (${f.source})`);
  }
  for(const w of result.warnings||[])lines.push(`WARNING: ${w}`);
  return lines.join('\n')+'\n';
}

async function scan(msg){
  await ensureOptionalPackage(msg.name);
  const bytes=new Uint8Array(msg.bytes);
  const {dir,path}=writeInput(msg.name,msg.bytes,msg.id);
  try{
    const json=await pyString(
      "import json; from pathlib import Path; json.dumps(scan_file(Path(db_path), db_name).to_dict(), ensure_ascii=False)",
      {db_path:path,db_name:msg.name}
    );
    const result=JSON.parse(json);
    return await enrichScan(msg.name,bytes,result);
  }finally{
    await pyString("import shutil; shutil.rmtree(db_dir, ignore_errors=True)",{db_dir:dir});
  }
}

async function clean(msg){
  await ensureOptionalPackage(msg.name);
  const originalBytes=new Uint8Array(msg.bytes);
  const {dir,path}=writeInput(msg.name,msg.bytes,msg.id);
  try{
    const options=JSON.stringify(msg.options||{});
    const payload=await pyString(`
import json
from pathlib import Path
_result=clean_file(Path(db_path),Path(db_dir),CleanMode(db_mode),NormalizationProfile(db_profile),db_name,json.loads(db_options))
json.dumps({"result":_result.to_dict(),"output_path":_result.output_path},ensure_ascii=False)
`,{db_path:path,db_dir:dir,db_name:msg.name,db_mode:msg.mode,db_profile:msg.profile,db_options:options});
    const parsed=JSON.parse(payload);
    const outBytes=pyodide.FS.readFile(parsed.output_path);
    const fileBytes=outBytes.slice().buffer;

    parsed.result.original=await enrichScan(msg.name,originalBytes,parsed.result.original);
    parsed.result.sanitized=await enrichScan(
      parsed.output_path.split('/').pop(),
      outBytes,
      parsed.result.sanitized
    );
    parsed.result.diff=buildFullDiff(parsed.result.original,parsed.result.sanitized);
    parsed.result.warnings=[
      ...(parsed.result.warnings||[]),
      ...(parsed.result.diff.warnings||[])
    ];

    return {
      result:parsed.result,
      fileBytes,
      fileName:parsed.output_path.split('/').pop(),
      reportJson:fullJsonReport(parsed.result),
      reportText:fullTextReport(parsed.result)
    };
  }finally{
    await pyString("import shutil; shutil.rmtree(db_dir, ignore_errors=True)",{db_dir:dir});
  }
}

(async()=>{
  try{await init();postMessage({type:'ready'})}
  catch(error){postMessage({type:'fatal',error:String(error?.stack||error)})}
})();

onmessage=async event=>{
  const msg=event.data||{};
  if(!msg.id)return;
  try{
    const result=msg.action==='scan'
      ?await scan(msg)
      :msg.action==='clean'
        ?await clean(msg)
        :(()=>{throw new Error('Unknown browser-engine action')})();
    const transfer=result?.fileBytes instanceof ArrayBuffer?[result.fileBytes]:[];
    postMessage({id:msg.id,ok:true,result},transfer);
  }catch(error){
    postMessage({id:msg.id,ok:false,error:String(error?.stack||error)});
  }
};
