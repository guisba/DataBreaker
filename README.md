<div align="center">

# DataBreaker

**Local-first metadata analysis, provenance inspection, privacy cleaning and verification.**

English · Português (Brasil) &nbsp; | &nbsp; No telemetry &nbsp; | &nbsp; Files stay on your machine

[Use DataBreaker online](https://databreaker-ashy.vercel.app/) · [Public documentation](https://caveras-personal-organization.gitbook.io/databreaker/) · [Releases](https://github.com/guisba/DataBreaker/releases)

</div>

## Interface preview

![DataBreaker black/white interface](docs/preview-v0.2.jpg)

DataBreaker v0.3 keeps the restrained black/white interface with an optional red/black theme. The workflow stays focused on evidence instead of decorative effects: drop files → inspect findings → choose a cleaning policy → verify **Original → Sanitized**.

[Read the full accessible interface description](docs/INTERFACE.md)

DataBreaker answers a practical question before you share a file: **what can this file reveal about where it came from?** It inspects ordinary metadata, obscure/custom blocks, origin fingerprints, AI workflow traces and cryptographic provenance, explains the evidence, cleans what it can safely rewrite, then reopens and rescans the output instead of trusting a “success” return code.

> DataBreaker is intentionally conservative. It does not promise universal metadata removal, does not silently delete document content, and does not claim that absence of known metadata proves absence of provenance or watermarking.

## Features

- Drag-and-drop multi-file workflow with restrained black/white and red/black themes, responsive EN/PT-BR UI, and persistent theme preference.
- Origin/Fingerprint Analyzer with evidence, source location, privacy impact and confidence levels.
- Safe Clean, Deep Clean and Clean Everything policies.
- Independent post-clean validation + second metadata scan + before/after diff.
- JSON reports suitable for audits or automation.
- Direct structural parsing of JPEG, PNG, WebP, ISO-BMFF/QuickTime, OOXML and archives.
- PDF metadata/content-structure separation and signature warnings.
- Audio metadata support through Mutagen without transcoding.
- **Full browser metadata inventory powered by ExifTool 13.59 in WebAssembly** with duplicate tags, unknown tags, embedded documents and deep extraction enabled.
- Local ExifTool, when available, uses the same full-inventory strategy in read-only mode.
- Every field returned by the inventory engine stays visible; unknown/proprietary fields are shown raw instead of silently discarded.
- C2PA/JUMBF/CBOR provenance is expanded into individual fields such as actions, claim-generator data, hashes, assertion URLs, signature-related values and unknown future fields.
- One-click **Copy all** plus JSON/text reports for field-by-field inspection.
- AI workflow indicators for C2PA/Content Credentials, Stable Diffusion/AUTOMATIC1111-style parameters, ComfyUI-style prompt/workflow metadata and other documented signals.
- Security limits for hostile files, archive traversal, decompression ratios, oversized metadata and malformed structures.
- No analytics or behavioral telemetry. The local and browser-only editions do not upload file contents to a DataBreaker backend; a separately hosted server deployment is explicitly identified and uses temporary request-scoped processing.

## Supported formats

| Format | Analyze | Clean | Notes |
| --- | :---: | :---: | --- |
| JPEG/JPG | ✓ | ✓ | Lossless marker rewrite; EXIF/XMP/IRB/ICC/JUMBF/unknown APP inspection |
| PNG | ✓ | ✓ | CRC validation; text/eXIf/iCCP/unknown ancillary chunks; IDAT preserved |
| WebP | ✓ | ✓ | RIFF EXIF/XMP/ICC; VP8X flags repaired; no image transcoding |
| GIF | ✓ | — | Full ExifTool inventory including comments/application extensions/C2PA where present |
| JFIF | ✓ | ✓* | Detected as JPEG; JFIF/EXIF/XMP/JUMBF inventory exposed |
| DNG/CR2/CR3/NEF/ARW/ORF/PEF/CRW/RAF/RW2/RAW | ✓ | — | ExifTool 13.59 full inventory; analysis-only unless a native safe writer exists |
| SVG | ✓ | ✓ | Metadata/editor namespace inspection; cleaning reserializes XML |
| PDF | ✓ | ✓* | Conservative metadata rewrite; signatures/incremental history can be invalidated |
| DOCX/XLSX/PPTX | ✓ | ✓ | Package properties + ZIP metadata; comments/revisions remain content |
| ZIP | ✓ | ✓ | Entry payloads preserved; metadata normalized according to mode |
| TAR | ✓ | — | UID/GID, user/group, timestamps, paths |
| MP3/FLAC/OGG/WAV | ✓ | ✓ | Structured tag removal via Mutagen, no audio transcoding |
| MP4/MOV/M4A/M4V | ✓ | ✓† | QuickTime/ISO-BMFF + ExifTool deep inventory; native cleaning where supported |
| HEIF/HEIC/AVIF | ✓ | — | Conservative ISO-BMFF analysis; automatic rewrite intentionally disabled |
| Matroska/WebM | basic | — | Container recognized; full EBML metadata cleaner is roadmap |
| 7z | basic | — | Container recognized; deep parser is roadmap |

`*` PDF cleaning rewrites document structure and therefore cannot preserve an existing byte-level digital signature. `†` M4V is analyzed through the full inventory layer but may be analysis-only if the native writer does not advertise safe cleaning.

## Full metadata inventory

DataBreaker v0.3 uses **ExifTool 13.59 as the browser inventory baseline**, running locally through WebAssembly/ZeroPerl. The browser invokes ExifTool with duplicate and unknown tags enabled, deep embedded extraction (`-ee3`) and `RequestAll=3`. This is intentionally broader than a fixed hand-written list of EXIF/XMP fields.

The product rule is: **if ExifTool reports a field, DataBreaker does not hide it.** Known fields receive privacy/origin explanations; fields that are new, proprietary or not yet understood remain visible with their raw tag/group and value. Native DataBreaker parsers run alongside this inventory to validate containers, classify risk and perform verified cleaning.

This is also the parity strategy for viewers such as Pics.io: DataBreaker covers the common image/PDF/RAW/video families they advertise while retaining a raw fallback for additional ExifTool-supported formats. DataBreaker is not affiliated with Pics.io.

Filesystem-style values such as `FileAccessDate`, `FileInodeChangeDate` and `FilePermissions` are displayed too, but labeled **filesystem/runtime metadata**. In a browser sandbox or temporary processing directory they describe that runtime copy and must not be presented as embedded source-file metadata.

## What DataBreaker looks for

**Critical privacy exposure** — GPS/location, usernames, host-computer values, serial numbers, account/unique IDs and path leaks.

**Origin indicators** — manufacturer/model, camera/phone, scanner/printer hints, operating-system/application strings, editor/encoder versions, AI generation/editing workflow fields and provenance systems.

**General metadata** — authors, comments, timestamps, copyright, document properties, XMP/IPTC, archive timestamps/attributes, audio tags and application fields.

**Structural metadata** — ICC/color information, package structures and other fields that may be required for compatibility.

**Unknown/unclassified** — unknown JPEG APP segments, PNG ancillary chunks, XMP namespaces, OOXML custom XML, archive extras and other structures DataBreaker can expose without pretending to understand.

## Cleaning modes

**Safe Clean** removes common privacy-sensitive metadata while favoring compatibility. It is the default.

**Deep Clean** adds uncommon/application-specific fields where the format handler can remove them without touching primary content.

**Clean Everything** removes every known nonessential metadata field that the active handler can safely rewrite. It can remove provenance blocks and invalidate provenance/signatures. DataBreaker still refuses to silently delete document content such as tracked revisions, comments or attachments.

Normalization profiles control structural preservation and required placeholder values. **Preserve Compatibility** retains compatibility-sensitive data such as ICC profiles and package timestamps. **Minimal** uses the smallest valid structural placeholders where a container requires a field. **Generic** uses neutral, valid normalized values (for example a canonical ZIP timestamp) and records them as synthetic in the local report. **Custom** exposes explicit controls for preserving ICC/color profiles and archive/package timestamps. DataBreaker never fabricates device identities, real organizations, certificate chains or C2PA credentials.

## Origin confidence

- **Confirmed** — directly parsed structured metadata or parser result.
- **High confidence** — strong format/application-specific evidence.
- **Possible** — plausible but ambiguous origin indicator.
- **Weak indicator** — low-specificity hint.
- **Unknown** — unclassified structure.

Evidence remains visible in the finding. `Software = Adobe Photoshop` is an application fingerprint, not proof that Firefly was used; a valid signed Content Credential is a different class of evidence.

## Privacy model

DataBreaker supports three clearly identified execution models. The public browser edition runs the Python engine in the browser through Pyodide/WebAssembly, so selected file contents are not uploaded to a DataBreaker backend. The local edition runs FastAPI on `127.0.0.1` and keeps processing on the same machine. A separately hosted FastAPI deployment can use stateless request-scoped temporary storage, but that mode is not presented as equivalent to local/browser-only privacy. The application contains no analytics or behavioral telemetry.

The public browser edition bundles ExifTool 13.59/ZeroPerl WebAssembly for local read-only inventory. If a native ExifTool executable is already installed on the local machine, the desktop/local edition uses it for the same full-inventory purpose. DataBreaker does **not** automatically call online AI-detection or remote C2PA verification services. Content-level watermarks such as SynthID are not ordinary metadata and are not claimed as removable.

## Public browser edition

The browser-only Vercel edition is live at **https://databreaker-ashy.vercel.app/**. It runs the DataBreaker Python engine inside a WebAssembly/Pyodide worker. Files remain in the browser's local memory/filesystem rather than being uploaded to an application server.

The Vercel build vendors the Pyodide core runtime **and the ExifTool/ZeroPerl WebAssembly inventory engine** with the site. JPEG/PNG/RAW metadata inventory therefore runs in the browser without uploading the selected file to a DataBreaker backend. Formats that need optional Python parsers for native cleaning, such as PDF or audio, can still fetch those parser packages on demand. Browser memory, device performance and supported WebAssembly features remain practical limits; the project does not advertise literally unlimited processing.

See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) for the execution and threat models.

## Install and run

### Windows — easiest

1. Install Python 3.11 or newer.
2. Double-click `run.bat`.
3. The script creates `.venv`, installs only required Python packages, validates the environment and opens DataBreaker at `http://127.0.0.1:8732`.

`run.bat` supports both the Windows `py` launcher and standard `python` installations.

### macOS / Linux / manual Windows setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m databreaker
```

Open `http://127.0.0.1:8732` if the browser does not open automatically.

### ExifTool inventory

The public browser edition already includes an ExifTool 13.59 WebAssembly inventory engine. In the local Python edition, if a native `exiftool` is already on `PATH`, DataBreaker automatically uses that executable in **read-only full-inventory mode**. It never delegates a cleaning claim to ExifTool unless the sanitized file is independently rescanned.

## Usage

1. Drop one or more files.
2. Review the complete ExifTool inventory plus critical exposures, origin indicators, general/structural metadata and unknown fields. Use **Copy all** or JSON export when you want a flat field/value list.
3. Choose Safe, Deep or Clean Everything.
4. Review the policy warning and normalization profile.
5. Clean.
6. DataBreaker reopens the output, rescans metadata and creates the Original → Sanitized diff.
7. Download the sanitized file and/or JSON report.

The UI never displays “100% clean”. A successful result means the requested known fields were removed as far as the active handlers can verify; unknown or structural metadata is reported separately.

## Security model

DataBreaker treats files as hostile. Current protections include:

- 100 MB default per-file limit and 20-file upload limit.
- ZIP/TAR entry-count and aggregate-uncompressed-size limits.
- Nested archive expansion is disabled in 0.1, avoiding recursive decompression-bomb chains.
- compression-ratio warnings for bomb-like archives.
- archive path traversal detection and rejection during rewrite.
- bounded TIFF offsets/counts and metadata values.
- PNG CRC validation and explicit malformed-container failures.
- no execution of embedded scripts/macros/attachments.
- safe temporary directories and sanitized local output names.
- post-clean parser validation and metadata rescan.

Run DataBreaker as a normal user rather than administrator/root. Parser hardening is ongoing; report malformed-file crashes as security issues rather than attaching confidential sample files publicly.

## Development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt
python -m compileall databreaker
python -m pytest -q
python -m databreaker
```

Architecture details are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The source/specification review and product limitations are in [`docs/METADATA_RESEARCH.md`](docs/METADATA_RESEARCH.md). See also [`PRIVACY.md`](PRIVACY.md), [`SECURITY.md`](SECURITY.md), and the accessible [`docs/INTERFACE.md`](docs/INTERFACE.md).

## Testing

The automated suite covers structural detection, Safe/Deep/Clean Everything behavior, primary-content preservation, unknown metadata, AI workflow metadata, malformed PNGs, archive traversal, translation parity, full ExifTool browser bundling, Pics.io-baseline format recognition, C2PA/JUMBF field extraction, and a Chromium end-to-end upload/clean test. CI runs on Python 3.11–3.13.

## Limitations

- DataBreaker exposes every field returned by ExifTool 13.59 plus native-parser unknown structures, but no program can assign semantics to a future/proprietary format it has never seen. Such fields remain visible raw instead of being silently omitted.
- SynthID and similar content-level watermarks are not metadata blocks.
- HEIF/AVIF, Matroska/WebM and 7z need deeper safe writers before automatic cleaning is enabled.
- Nested archives are reported as member payloads but are not recursively scanned in 0.1.
- PDF structural rewriting invalidates byte-level signatures and can remove incremental-update history.
- Document comments, revisions, attachments and custom XML may be content/functionality, so they are not silently deleted.
- ICC/color profiles may affect rendering; removing them can change appearance in color-managed software.
- Absence of an AI marker is not proof of human origin, and editable plaintext metadata is never treated as cryptographic proof.

## Roadmap

Highest-value next work: native HEIF/AVIF item-property rewriting with conformance fixtures; full EBML/Matroska parsing; opt-in offline C2PA signature validation; deeper OOXML relationship-aware removal operations with explicit content confirmation; file-format corpus/fuzz testing; and signed release packaging for desktop users.

## Research

DataBreaker’s behavior is based on primary specifications and documented implementations where possible, including W3C PNG, Google WebP, CIPA EXIF, IPTC, C2PA, Apple QuickTime metadata, ECMA-376 OOXML, ID3/Xiph and documented AI-tool export behavior. See [`docs/METADATA_RESEARCH.md`](docs/METADATA_RESEARCH.md) for sources and false-positive notes.
