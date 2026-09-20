# Privacy

DataBreaker has three execution models. The UI identifies which model is active.

## Browser-only public edition

The public Vercel edition runs the metadata engine inside the browser using Pyodide/WebAssembly. Selected files are read by the browser and processed in its local WebAssembly filesystem. DataBreaker does not upload those files to an application backend.

The static Vercel build vendors the Pyodide core runtime, DataBreaker module source, and the ExifTool 13.59/ZeroPerl WebAssembly inventory engine with the site. Metadata extraction runs against the selected browser `File` locally. JPEG/PNG/RAW inventory therefore does not require sending selected file bytes to a DataBreaker backend. Formats that need optional Python parsers for native cleaning, such as PDF or audio, can fetch those parser packages on demand from Python/Pyodide package infrastructure. Standard hosting/package access logs may exist for application/runtime/parser downloads, but those requests do not intentionally contain the selected file bytes. ExifTool-WASM itself is bundled with the static deployment rather than called as a remote metadata API.

## Local edition

The local Python edition binds FastAPI to `127.0.0.1`. The browser sends files only to that loopback service. Temporary files are stored on the local machine and cleaned with the process temporary directory lifecycle.

## Server-hosted edition

If someone deploys the FastAPI application to a server, DataBreaker switches to stateless hosted behavior when the `VERCEL` or `DATABREAKER_STATELESS` environment flag is present. Files are written to temporary server storage for the active request and the working directory is deleted after the operation. This is **not equivalent to local or browser-only processing**: the hosting provider may have infrastructure logs, snapshots, network controls, quotas, and retention policies outside DataBreaker's control.

## Telemetry

The DataBreaker codebase does not include analytics or behavioral telemetry. Reports are generated for the user and are not automatically transmitted elsewhere.

## Provenance and watermarks

Removing metadata does not necessarily remove content-level provenance or watermarks. In particular, content-level systems such as SynthID are outside ordinary metadata cleaning.


## Full-inventory filesystem fields

ExifTool can report runtime/filesystem attributes such as `FileName`, `FileSize`, `FileModifyDate`, `FileAccessDate`, inode-change time and permissions. DataBreaker exposes these values because they are part of the complete inventory, but labels them **filesystem/runtime metadata**. In browser mode they may describe the sandbox/runtime representation rather than metadata embedded inside the original asset.
