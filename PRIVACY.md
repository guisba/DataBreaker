# Privacy

DataBreaker has three execution models. The UI identifies which model is active.

## Browser-only public edition

The public browser edition at https://databreaker-pcdnak.v2.appdeploy.ai/ runs the metadata engine inside the browser using Pyodide/WebAssembly. Selected files are read by the browser and processed in its local WebAssembly filesystem. DataBreaker does not upload those files to an application backend.

The first use downloads the web application, Pyodide runtime, Python parser dependencies, and DataBreaker module source from public hosting/CDN/GitHub infrastructure. Standard host/CDN access logs may therefore exist for application/runtime downloads, but those requests do not intentionally contain the selected file bytes.

## Local edition

The local Python edition binds FastAPI to `127.0.0.1`. The browser sends files only to that loopback service. Temporary files are stored on the local machine and cleaned with the process temporary directory lifecycle.

## Server-hosted edition

If someone deploys the FastAPI application to a server, DataBreaker switches to stateless hosted behavior when the `VERCEL` or `DATABREAKER_STATELESS` environment flag is present. Files are written to temporary server storage for the active request and the working directory is deleted after the operation. This is **not equivalent to local or browser-only processing**: the hosting provider may have infrastructure logs, snapshots, network controls, quotas, and retention policies outside DataBreaker's control.

## Telemetry

The DataBreaker codebase does not include analytics or behavioral telemetry. Reports are generated for the user and are not automatically transmitted elsewhere.

## Provenance and watermarks

Removing metadata does not necessarily remove content-level provenance or watermarks. In particular, content-level systems such as SynthID are outside ordinary metadata cleaning.
